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
    * We reserve 0x40000 at the end of the flash for persistent storage.
    */
  FLASH (X) : ORIGIN = 0x20040000, LENGTH = 256K
  RAM   (W) : ORIGIN = 0x10005480, LENGTH = 128K
}

TBF_HEADER_SIZE = 0x60;
INCLUDE libtock_layout.ld
