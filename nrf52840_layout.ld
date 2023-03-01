/* Layout for the nRF52840-DK and nRF52840 dongle, used by the
 * app in this repository.
 */

MEMORY {
  /* The application region is 64 bytes (0x40) and we reserve 0x40000 at the end
   * of the flash for the persistent storage.
   */
  FLASH (X) : ORIGIN = 0x00040040, LENGTH = 0x0007FFC0
  RAM (W) : ORIGIN = 0x20020000, LENGTH = 128K
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
