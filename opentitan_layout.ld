/* Layout for the OpenTitan board (CW310), emulating the Ibex processor,
 * used by app in this repository.
 */

MEMORY {
  /* Note that the SRAM address may need to be changed depending on
   * the kernel binary, check for the actual address of APP_MEMORY!
   * Can be found out with enabling the `debug_load_processes` feature 
   * for TockOs!
   */

   /* OpenTitan has 2x512kB banks of flash memory and 128kB SRAM.
      We reserve 0x20_000 at the end of the flash for persistent storage.
    */
  FLASH (X) : ORIGIN = 0x20030000, LENGTH = 0x40000
  RAM   (W) : ORIGIN = 0x1000466C, LENGTH = 128K
}

/*
 * Any change to STACK_SIZE should be accompanied by a corresponding change to
 * `elf2tab`'s `--stack` option
 */
STACK_SIZE = 16384;

MPU_MIN_ALIGN = 8K;

/*
 * Any change to TBF_HEADER_SIZE should be accompanied by a corresponding change to
 * `elf2tab`'s `--protected_region_size` option
 */
TBF_HEADER_SIZE = 0x60;

INCLUDE libtock_layout.ld
