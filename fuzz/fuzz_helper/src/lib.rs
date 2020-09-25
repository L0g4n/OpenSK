// Copyright 2019 Google LLC
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

// This explicit "extern crate" is needed to make the linker aware of the
// `libtock_alloc_init` symbol.
extern crate lang_items;

use arrayref::array_ref;
use core::convert::TryFrom;
use crypto::rng256::ThreadRng256;
use ctap2::ctap::command::{
    AuthenticatorClientPinParameters, AuthenticatorGetAssertionParameters,
    AuthenticatorMakeCredentialParameters,
};
use ctap2::ctap::hid::receive::MessageAssembler;
use ctap2::ctap::hid::send::HidPacketIterator;
use ctap2::ctap::hid::{ChannelID, CtapHid, HidPacket, Message};
use ctap2::ctap::status_code::Ctap2StatusCode;
use ctap2::ctap::CtapState;
use libtock_drivers::timer::{ClockValue, Timestamp};

const COMMAND_INIT: u8 = 0x06;
const CHANNEL_BROADCAST: ChannelID = [0xFF, 0xFF, 0xFF, 0xFF];
const PACKET_TYPE_MASK: u8 = 0x80;

const CLOCK_FREQUENCY_HZ: usize = 32768;
const DUMMY_TIMESTAMP: Timestamp<isize> = Timestamp::from_ms(0);
const DUMMY_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);

#[derive(Clone, PartialEq)]
pub enum InputType {
    CborMakeCredentialParameter,
    CborGetAssertionParameter,
    CborClientPinParameter,
    Ctap1,
}

// Converts a byte slice into Message
fn raw_to_message(data: &[u8]) -> Message {
    if data.len() <= 4 {
        let mut cid = [0; 4];
        cid[..data.len()].copy_from_slice(data);
        Message {
            cid,
            cmd: 0,
            payload: vec![],
        }
    } else {
        Message {
            cid: array_ref!(data, 0, 4).clone(),
            cmd: data[4],
            payload: data[5..].to_vec(),
        }
    }
}

// Returns an initialized ctap state, hid and the allocated cid
// after processing the init command.
fn initialize<CheckUserPresence>(
    ctap_state: &mut CtapState<ThreadRng256, CheckUserPresence>,
    ctap_hid: &mut CtapHid,
) -> ChannelID
where
    CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
{
    let nonce = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let message = Message {
        cid: CHANNEL_BROADCAST,
        cmd: COMMAND_INIT,
        payload: nonce.clone(),
    };
    let mut assembler_reply = MessageAssembler::new();
    let mut result_cid: ChannelID = Default::default();
    for pkt_request in HidPacketIterator::new(message.clone()).unwrap() {
        for pkt_reply in ctap_hid.process_hid_packet(&pkt_request, DUMMY_CLOCK_VALUE, ctap_state) {
            if let Ok(Some(result)) = assembler_reply.parse_packet(&pkt_reply, DUMMY_TIMESTAMP) {
                result_cid.copy_from_slice(&result.payload[8..12]);
            }
        }
    }
    result_cid
}

// Checks whether the given data can be interpreted as the given type.
fn is_type(data: &[u8], input_type: InputType) -> bool {
    if input_type.clone() == InputType::Ctap1 {
        return true;
    }
    match cbor::read(data) {
        Err(_) => false,
        Ok(decoded_cbor) => match input_type {
            InputType::CborMakeCredentialParameter => {
                AuthenticatorMakeCredentialParameters::try_from(decoded_cbor).is_ok()
            }
            InputType::CborGetAssertionParameter => {
                AuthenticatorGetAssertionParameters::try_from(decoded_cbor).is_ok()
            }
            InputType::CborClientPinParameter => {
                AuthenticatorClientPinParameters::try_from(decoded_cbor).is_ok()
            }
            _ => true,
        },
    }
}

// Interprets the raw data as of the given input type and
// invokes message splitting, assembling and packet processing at CTAP HID level.
pub fn process_input(data: &[u8], input_type: InputType) {
    if !is_type(data, input_type.clone()) {
        return ();
    }
    // Initialize ctap state and hid and get the allocated cid.
    let mut rng = ThreadRng256 {};
    let user_immediately_present = |_| Ok(());
    let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);
    let mut ctap_hid = CtapHid::new();
    let cid = initialize(&mut ctap_state, &mut ctap_hid);
    // Wrap input as message with allocated cid and command type.
    let mut command = cid.to_vec();
    match input_type {
        InputType::CborMakeCredentialParameter => {
            command.extend(&[0x10, 0x01]);
        }
        InputType::CborGetAssertionParameter => {
            command.extend(&[0x10, 0x02]);
        }
        InputType::CborClientPinParameter => {
            command.extend(&[0x10, 0x06]);
        }
        InputType::Ctap1 => {
            command.extend(&[0x03]);
        }
    }
    command.extend(data);
    // Process message at HID level.
    let message = raw_to_message(&command);
    if let Some(hid_packet_iterator) = HidPacketIterator::new(message) {
        let mut assembler_reply = MessageAssembler::new();
        for pkt_request in hid_packet_iterator {
            for pkt_reply in
                ctap_hid.process_hid_packet(&pkt_request, DUMMY_CLOCK_VALUE, &mut ctap_state)
            {
                // Only checks for assembling crashes, not for semantics.
                let _ = assembler_reply.parse_packet(&pkt_reply, DUMMY_TIMESTAMP);
            }
        }
    }
}

// Splits and reassembles the given data as HID packets.
pub fn split_assemble(data: &[u8]) {
    let mut message = raw_to_message(data);
    if let Some(hid_packet_iterator) = HidPacketIterator::new(message.clone()) {
        let mut assembler = MessageAssembler::new();
        let packets: Vec<HidPacket> = hid_packet_iterator.collect();
        if let Some((last_packet, first_packets)) = packets.split_last() {
            for packet in first_packets {
                assert_eq!(assembler.parse_packet(packet, DUMMY_TIMESTAMP), Ok(None));
            }
            message.cmd &= !PACKET_TYPE_MASK;
            assert_eq!(
                assembler.parse_packet(last_packet, DUMMY_TIMESTAMP),
                Ok(Some(message))
            );
        }
    }
}
