// Copyright 2019-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::api::upgrade_storage::helper::{find_slice, is_aligned, ModRange, Partition};
use crate::api::upgrade_storage::UpgradeStorage;
use alloc::borrow::Cow;
use alloc::vec::Vec;
use arrayref::array_ref;
use byteorder::{ByteOrder, LittleEndian};
use core::cell::Cell;
use core::marker::PhantomData;
use crypto::sha256::Sha256;
use crypto::{ecdsa, Hash256};
use libtock_platform as platform;
use libtock_platform::{syscall_class, ErrorCode, RawSyscalls, Syscalls};
use persistent_store::{Storage, StorageError, StorageIndex, StorageResult};
use platform::share;

const DRIVER_NUMBER: u32 = 0x50003;
const METADATA_SIGN_OFFSET: usize = 0x800;

const UPGRADE_PUBLIC_KEY: &[u8; 65] =
    include_bytes!(concat!(env!("OUT_DIR"), "/opensk_upgrade_pubkey.bin"));

mod subscribe_nr {
    pub const DONE: u32 = 0;
}

mod command_nr {
    pub const GET_INFO: u32 = 1;
    pub mod get_info_nr {
        pub const WORD_SIZE: u32 = 0;
        pub const PAGE_SIZE: u32 = 1;
        pub const MAX_WORD_WRITES: u32 = 2;
        pub const MAX_PAGE_ERASES: u32 = 3;
    }
    pub const WRITE_SLICE: u32 = 2;
    pub const ERASE_PAGE: u32 = 3;
}

mod ro_allow_nr {
    pub const WRITE_SLICE: u32 = 0;
}

mod memop_nr {
    pub const STORAGE_CNT: u32 = 12;
    pub const STORAGE_PTR: u32 = 13;
    pub const STORAGE_LEN: u32 = 14;
    pub const STORAGE_TYPE: u32 = 15;
}

mod storage_type {
    pub const STORE: u32 = 1;
    pub const PARTITION: u32 = 2;
}

fn get_info<S: Syscalls>(nr: u32, arg: u32) -> StorageResult<u32> {
    let info =
        S::command(DRIVER_NUMBER, command_nr::GET_INFO, nr, arg).to_result::<u32, ErrorCode>()?;
    Ok(info)
}

fn memop<S: RawSyscalls>(nr: u32, arg: u32) -> StorageResult<u32> {
    let registers = unsafe { S::syscall2::<{ syscall_class::MEMOP }>([nr.into(), arg.into()]) };

    let r0 = registers[0].as_u32();
    let r1 = registers[1].as_u32();

    // make sure r0 is the `success with u32` (129) return variant and then return the value in r1 as u32
    // see: https://github.com/tock/tock/blob/master/doc/reference/trd104-syscalls.md#32-return-values
    match (r0, r1) {
        (129, r1) => Ok(r1),
        (_, _) => Err(StorageError::LibtockRsError(ErrorCode::BadRVal)),
    }
}

fn block_command<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config>(
    driver: u32,
    cmd: u32,
    arg1: u32,
    arg2: u32,
) -> StorageResult<()> {
    use core::fmt::Write;
    use libtock_console::Console;
    let mut writer = Console::<S>::writer();
    writeln!(writer, "beginning of block command").unwrap();
    let called: Cell<Option<(u32,)>> = Cell::new(None);

    share::scope(|subscribe| {
        S::subscribe::<_, _, C, DRIVER_NUMBER, { subscribe_nr::DONE }>(subscribe, &called)?;
        writeln!(
            writer,
            "before cmd; driver: {}, cmd: {}, arg1: {}, arg2: {}",
            driver, cmd, arg1, arg2
        )
        .unwrap();
        S::command(driver, cmd, arg1, arg2).to_result::<(), ErrorCode>()?;
        libtock_drivers::util::Util::<S>::yieldk_for(|| called.get().is_some());
        writeln!(writer, "end of block command").unwrap();
        if called.get().unwrap().0 == 0 {
            Ok(())
        } else {
            Err(StorageError::LibtockRsError(ErrorCode::Invalid))
        }
    })
}

unsafe fn read_slice(address: usize, length: usize) -> &'static [u8] {
    core::slice::from_raw_parts(address as *const u8, length)
}

fn write_slice<S: Syscalls, C: platform::allow_ro::Config + platform::subscribe::Config>(
    ptr: usize,
    value: &[u8],
) -> StorageResult<()> {
    use core::fmt::Write;
    use libtock_console::Console;
    let mut writer = Console::<S>::writer();
    writeln!(
        writer,
        "beginning of write slice command: ptr: {}, value: {:?}",
        ptr, value
    )
    .unwrap();
    share::scope(|allow_ro| {
        S::allow_ro::<C, DRIVER_NUMBER, { ro_allow_nr::WRITE_SLICE }>(allow_ro, value)?;
        block_command::<S, C>(
            DRIVER_NUMBER,
            command_nr::WRITE_SLICE,
            ptr as u32,
            value.len() as u32,
        )
    })
}

fn erase_page<S: Syscalls, C: platform::allow_ro::Config + platform::subscribe::Config>(
    ptr: usize,
    page_length: usize,
) -> StorageResult<()> {
    use core::fmt::Write;
    use libtock_console::Console;
    let mut writer = Console::<S>::writer();
    writeln!(writer, "beginning of erase page command").unwrap();
    block_command::<S, C>(
        DRIVER_NUMBER,
        command_nr::ERASE_PAGE,
        ptr as u32,
        page_length as u32,
    )
}

pub struct TockStorage<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> {
    word_size: usize,
    page_size: usize,
    num_pages: usize,
    max_word_writes: usize,
    max_page_erases: usize,
    storage_locations: Vec<&'static [u8]>,
    _marker_s: PhantomData<S>,
    _marker_c: PhantomData<C>,
}

impl<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> TockStorage<S, C> {
    /// Provides access to the embedded flash if available.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The word size is a power of two.
    /// - The page size is a power of two.
    /// - The page size is a multiple of the word size.
    /// - The storage is page-aligned.
    pub fn new() -> StorageResult<TockStorage<S, C>> {
        let mut syscall = TockStorage {
            word_size: get_info::<S>(command_nr::get_info_nr::WORD_SIZE, 0)? as usize,
            page_size: get_info::<S>(command_nr::get_info_nr::PAGE_SIZE, 0)? as usize,
            num_pages: 0,
            max_word_writes: get_info::<S>(command_nr::get_info_nr::MAX_WORD_WRITES, 0)? as usize,
            max_page_erases: get_info::<S>(command_nr::get_info_nr::MAX_PAGE_ERASES, 0)? as usize,
            storage_locations: Vec::new(),
            _marker_s: PhantomData,
            _marker_c: PhantomData,
        };
        if !syscall.word_size.is_power_of_two()
            || !syscall.page_size.is_power_of_two()
            || !syscall.is_word_aligned(syscall.page_size)
        {
            return Err(StorageError::CustomError);
        }
        let num_storage_locations = memop::<S>(memop_nr::STORAGE_CNT, 0)?;
        for i in 0..num_storage_locations {
            if memop::<S>(memop_nr::STORAGE_TYPE, i)? != storage_type::STORE {
                continue;
            }
            let storage_ptr = memop::<S>(memop_nr::STORAGE_PTR, i)? as usize;
            let storage_len = memop::<S>(memop_nr::STORAGE_LEN, i)? as usize;
            if !syscall.is_page_aligned(storage_ptr) || !syscall.is_page_aligned(storage_len) {
                return Err(StorageError::CustomError);
            }
            syscall.num_pages += storage_len / syscall.page_size;
            syscall
                .storage_locations
                .push(unsafe { core::slice::from_raw_parts(storage_ptr as *mut u8, storage_len) });
        }
        Ok(syscall)
    }

    fn is_word_aligned(&self, x: usize) -> bool {
        is_aligned(self.word_size, x)
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }
}

impl<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> Storage
    for TockStorage<S, C>
{
    fn word_size(&self) -> usize {
        self.word_size
    }

    fn page_size(&self) -> usize {
        self.page_size
    }

    fn num_pages(&self) -> usize {
        self.num_pages
    }

    fn max_word_writes(&self) -> usize {
        self.max_word_writes
    }

    fn max_page_erases(&self) -> usize {
        self.max_page_erases
    }

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<[u8]>> {
        let start = index.range(length, self)?.start;
        find_slice(&self.storage_locations, start, length).map(Cow::Borrowed)
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        if !self.is_word_aligned(index.byte) || !self.is_word_aligned(value.len()) {
            return Err(StorageError::NotAligned);
        }
        let ptr = self.read_slice(index, value.len())?.as_ptr() as usize;
        write_slice::<S, C>(ptr, value)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = StorageIndex { page, byte: 0 };
        let length = self.page_size();
        let ptr = self.read_slice(index, length)?.as_ptr() as usize;
        erase_page::<S, C>(ptr, length)
    }
}

pub struct TockUpgradeStorage<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
> {
    page_size: usize,
    partition: Partition,
    metadata: ModRange,
    running_metadata: ModRange,
    identifier: u32,
    s: PhantomData<S>,
    c: PhantomData<C>,
}

impl<S, C> TockUpgradeStorage<S, C>
where
    S: Syscalls,
    C: platform::allow_ro::Config + platform::subscribe::Config,
{
    // Ideally, the kernel should tell us metadata and partitions directly.
    // This code only works for one layout, refactor this into the storage driver to support more.
    const METADATA_ADDRESS: usize = 0x4000;
    const PARTITION_ADDRESS_A: usize = 0x20000;
    const PARTITION_ADDRESS_B: usize = 0x60000;

    /// Provides access to the other upgrade partition and metadata if available.
    ///
    /// The implementation assumes that storage locations returned by the kernel through
    /// `memop_nr::STORAGE_*` calls are in address space order.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The page size is a power of two.
    /// - The storage slices are page-aligned.
    /// - There are no partition or no metadata slices.
    /// Returns a `NotAligned` error if partitions or metadata ranges are
    /// - not exclusive or,
    /// - not consecutive.
    pub fn new() -> StorageResult<TockUpgradeStorage<S, C>> {
        let mut locations = TockUpgradeStorage {
            page_size: get_info::<S>(command_nr::get_info_nr::PAGE_SIZE, 0)? as usize,
            partition: Partition::new(),
            metadata: ModRange::new_empty(),
            running_metadata: ModRange::new_empty(),
            identifier: Self::PARTITION_ADDRESS_A as u32,
            s: PhantomData,
            c: PhantomData,
        };
        if !locations.page_size.is_power_of_two() {
            return Err(StorageError::CustomError);
        }
        let mut firmware_range = ModRange::new_empty();
        for i in 0..memop::<S>(memop_nr::STORAGE_CNT, 0)? {
            let storage_type = memop::<S>(memop_nr::STORAGE_TYPE, i)?;
            if !matches!(storage_type, storage_type::PARTITION) {
                continue;
            };
            let storage_ptr = memop::<S>(memop_nr::STORAGE_PTR, i)? as usize;
            let storage_len = memop::<S>(memop_nr::STORAGE_LEN, i)? as usize;
            if !locations.is_page_aligned(storage_ptr) || !locations.is_page_aligned(storage_len) {
                return Err(StorageError::CustomError);
            }
            let range = ModRange::new(storage_ptr, storage_len);
            match range.start() {
                Self::METADATA_ADDRESS => {
                    // Will be swapped if we are on B.
                    locations.metadata = ModRange::new(range.start(), locations.page_size);
                    locations.running_metadata =
                        ModRange::new(range.start() + locations.page_size, locations.page_size);
                }
                _ => {
                    if !firmware_range.append(&range) {
                        return Err(StorageError::NotAligned);
                    }
                }
            }
        }
        if firmware_range.is_empty()
            || locations.metadata.is_empty()
            || locations.running_metadata.is_empty()
        {
            return Err(StorageError::CustomError);
        }
        if firmware_range.start() == Self::PARTITION_ADDRESS_B {
            core::mem::swap(&mut locations.metadata, &mut locations.running_metadata);
            locations.identifier = Self::PARTITION_ADDRESS_B as u32;
        }
        if !locations.partition.append(locations.metadata.clone()) {
            return Err(StorageError::NotAligned);
        }
        if !locations.partition.append(firmware_range) {
            return Err(StorageError::NotAligned);
        }
        Ok(locations)
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }

    /// Returns whether the metadata is contained in this range or not.
    ///
    /// Assumes that metadata is written in one call per range. If the metadata is only partially
    /// contained, returns an error.
    fn contains_metadata(&self, checked_range: &ModRange) -> StorageResult<bool> {
        if checked_range.intersects_range(&self.metadata) {
            if checked_range.contains_range(&self.metadata) {
                Ok(true)
            } else {
                Err(StorageError::NotAligned)
            }
        } else {
            Ok(false)
        }
    }

    /// Checks if the metadata's hash matches the partition's content.
    fn check_partition_hash(&self, metadata: &[u8]) -> StorageResult<()> {
        let start_address = self.metadata.start() + METADATA_SIGN_OFFSET;
        let mut hasher = Sha256::new();
        for range in self.partition.ranges_from(start_address) {
            let partition_slice = unsafe { read_slice(range.start(), range.length()) };
            // The hash implementation handles this in chunks, so no memory issues.
            hasher.update(partition_slice);
        }
        let computed_hash = hasher.finalize();
        if &computed_hash != parse_metadata_hash(metadata) {
            return Err(StorageError::CustomError);
        }
        Ok(())
    }
}

impl<S, C> UpgradeStorage for TockUpgradeStorage<S, C>
where
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
{
    fn write_bundle(&mut self, offset: usize, data: Vec<u8>) -> StorageResult<()> {
        if data.is_empty() {
            return Err(StorageError::OutOfBounds);
        }
        let address = self
            .partition
            .find_address(offset, data.len())
            .ok_or(StorageError::OutOfBounds)?;
        let write_range = ModRange::new(address, data.len());
        if self.contains_metadata(&write_range)? {
            let new_metadata = &data[self.metadata.start() - address..][..self.metadata.length()];
            check_metadata(self, UPGRADE_PUBLIC_KEY, new_metadata)?;
        }

        // Erases all pages that have their first byte in the write range.
        // Since we expect calls in order, we don't want to erase half-written pages.
        for address in write_range.aligned_iter(self.page_size) {
            erase_page::<S, C>(address, self.page_size)?;
        }
        write_slice::<S, C>(address, &data)?;
        let written_slice = unsafe { read_slice(address, data.len()) };
        if written_slice != data {
            return Err(StorageError::CustomError);
        }
        // Case: Last slice is written.
        if data.len() == self.partition.length() - offset {
            let metadata = unsafe { read_slice(self.metadata.start(), self.metadata.length()) };
            self.check_partition_hash(metadata)?;
        }
        Ok(())
    }

    fn bundle_identifier(&self) -> u32 {
        self.identifier
    }

    fn running_firmware_version(&self) -> u64 {
        let running_metadata = unsafe {
            read_slice(
                self.running_metadata.start(),
                self.running_metadata.length(),
            )
        };
        parse_metadata_version(running_metadata)
    }
}

/// Parses the metadata of an upgrade, and checks its correctness.
///
/// The metadata is a page starting with:
/// - 32 B upgrade hash (SHA256)
/// - 64 B signature,
/// that are not signed over. The second part is included in the signature with
/// -  8 B version and
/// -  4 B partition address in little endian encoding
/// written at METADATA_SIGN_OFFSET.
///
/// Checks signature correctness against the hash, and whether the partition offset matches.
/// Whether the hash matches the partition content is not tested here!
fn check_metadata(
    upgrade_locations: &impl UpgradeStorage,
    public_key_bytes: &[u8],
    metadata: &[u8],
) -> StorageResult<()> {
    const METADATA_LEN: usize = 0x1000;
    if metadata.len() != METADATA_LEN {
        return Err(StorageError::CustomError);
    }

    let version = parse_metadata_version(metadata);
    if version < upgrade_locations.running_firmware_version() {
        return Err(StorageError::CustomError);
    }

    let metadata_address = LittleEndian::read_u32(&metadata[METADATA_SIGN_OFFSET + 8..][..4]);
    if metadata_address != upgrade_locations.bundle_identifier() {
        return Err(StorageError::CustomError);
    }

    verify_signature(
        array_ref!(metadata, 32, 64),
        public_key_bytes,
        parse_metadata_hash(metadata),
    )?;
    Ok(())
}

/// Parses the metadata, returns the hash.
fn parse_metadata_hash(data: &[u8]) -> &[u8; 32] {
    array_ref!(data, 0, 32)
}

/// Parses the metadata, returns the firmware version.
fn parse_metadata_version(data: &[u8]) -> u64 {
    LittleEndian::read_u64(&data[METADATA_SIGN_OFFSET..][..8])
}

/// Verifies the signature over the given hash.
///
/// The public key is COSE encoded, and the hash is a SHA256.
fn verify_signature(
    signature_bytes: &[u8; 64],
    public_key_bytes: &[u8],
    signed_hash: &[u8; 32],
) -> StorageResult<()> {
    let signature =
        ecdsa::Signature::from_bytes(signature_bytes).ok_or(StorageError::CustomError)?;
    let public_key = ecdsa::PubKey::from_bytes_uncompressed(public_key_bytes)
        .ok_or(StorageError::CustomError)?;
    if !public_key.verify_hash_vartime(signed_hash, &signature) {
        return Err(StorageError::CustomError);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;
    use crate::env::Env;

    #[test]
    fn test_check_metadata() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let upgrade_locations = env.upgrade_storage().unwrap();

        const METADATA_LEN: usize = 0x1000;
        const METADATA_SIGN_OFFSET: usize = 0x800;
        let mut metadata = vec![0xFF; METADATA_LEN];
        LittleEndian::write_u32(&mut metadata[METADATA_SIGN_OFFSET + 8..][..4], 0x60000);

        let mut signed_over_data = metadata[METADATA_SIGN_OFFSET..].to_vec();
        signed_over_data.extend([0xFF; 0x20000]);
        let signed_hash = Sha256::hash(&signed_over_data);

        metadata[..32].copy_from_slice(&signed_hash);
        let signature = private_key.sign_rfc6979::<Sha256>(&signed_over_data);
        let mut signature_bytes = [0; ecdsa::Signature::BYTES_LENGTH];
        signature.to_bytes(&mut signature_bytes);
        metadata[32..96].copy_from_slice(&signature_bytes);

        let public_key = private_key.genpk();
        let mut public_key_bytes = [0; 65];
        public_key.to_bytes_uncompressed(&mut public_key_bytes);

        assert_eq!(
            check_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Ok(())
        );

        // Manipulating the partition address fails.
        metadata[METADATA_SIGN_OFFSET + 8] = 0x88;
        assert_eq!(
            check_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
        metadata[METADATA_SIGN_OFFSET + 8] = 0x00;
        // Wrong metadata length fails.
        assert_eq!(
            check_metadata(
                upgrade_locations,
                &public_key_bytes,
                &metadata[..METADATA_LEN - 1]
            ),
            Err(StorageError::CustomError)
        );
        // Manipulating the hash fails.
        metadata[0] ^= 0x01;
        assert_eq!(
            check_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
        metadata[0] ^= 0x01;
        // Manipulating the signature fails.
        metadata[32] ^= 0x01;
        assert_eq!(
            check_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
    }

    #[test]
    fn test_verify_signature() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let message = [0x44; 64];
        let signed_hash = Sha256::hash(&message);
        let signature = private_key.sign_rfc6979::<Sha256>(&message);

        let mut signature_bytes = [0; ecdsa::Signature::BYTES_LENGTH];
        signature.to_bytes(&mut signature_bytes);

        let public_key = private_key.genpk();
        let mut public_key_bytes = [0; 65];
        public_key.to_bytes_uncompressed(&mut public_key_bytes);

        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &signed_hash),
            Ok(())
        );
        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &[0x55; 32]),
            Err(StorageError::CustomError)
        );
        public_key_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &signed_hash),
            Err(StorageError::CustomError)
        );
        public_key_bytes[0] ^= 0x01;
        signature_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &signed_hash),
            Err(StorageError::CustomError)
        );
    }
}
