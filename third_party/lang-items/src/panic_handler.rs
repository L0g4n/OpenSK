//! Custom panic handler for OpenSK

use crate::util;
#[cfg(feature = "panic_console")]
use core::fmt::Write;
#[cfg(feature = "panic_console")]
use libtock_console::Console;
use libtock_runtime::TockSyscalls;

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    util::Util::<TockSyscalls>::signal_panic();
    util::Util::<TockSyscalls>::flash_all_leds();

    #[cfg(feature = "panic_console")]
    {
        let mut writer = Console::<TockSyscalls>::writer();
        writeln!(writer, "{}", _info).ok();
        // Exit with a non-zero exit code to indicate failure.
        TockSyscalls::exit_terminate(ErrorCode::Fail as u32);
    }
}
