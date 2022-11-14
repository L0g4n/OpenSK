//! The alarm driver
//!
//! # Example
//! ```
//! // Wait for timeout
//! Alarm::sleep(Alarm::Milliseconds(2500));
//! ```
//!
//! Adapted from the [libtock-rs](https://github.com/tock/libtock-rs/blob/master/apis/alarm/src/lib.rs) alarm driver interface

use crate::result::TockResult;
use core::cell::Cell;
use core::marker::PhantomData;
use core::time::Duration;
use libtock_platform as platform;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};

pub struct Alarm<S: Syscalls, C: platform::subscribe::Config = DefaultConfig>(S, C);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Hz(pub u32);

pub trait Convert {
    /// Converts a time unit by rounding up.
    fn to_ticks(self, freq: Hz) -> Ticks;
}

#[derive(Copy, Clone, Debug)]
pub struct Ticks(pub u32);

impl Convert for Ticks {
    fn to_ticks(self, _freq: Hz) -> Ticks {
        self
    }
}

#[derive(Copy, Clone)]
pub struct Milliseconds(pub u32);

impl Convert for Milliseconds {
    fn to_ticks(self, freq: Hz) -> Ticks {
        // Saturating multiplication will top out at about 1 hour at 1MHz.
        // It's large enough for an alarm, and much simpler than failing
        // or losing precision for short sleeps.

        /// u32::div_ceil is still unstable.
        fn div_ceil(a: u32, other: u32) -> u32 {
            let d = a / other;
            let m = a % other;
            if m == 0 {
                d
            } else {
                d + 1
            }
        }
        Ticks(div_ceil(self.0.saturating_mul(freq.0), 1000))
    }
}

impl<S: Syscalls, C: platform::subscribe::Config> Alarm<S, C> {
    /// Run a check against the console capsule to ensure it is present.
    ///
    /// Returns number of concurrent notifications supported,
    /// 0 if unbounded.
    #[inline(always)]
    pub fn driver_check() -> Result<u32, ErrorCode> {
        S::command(DRIVER_NUM, command::DRIVER_CHECK, 0, 0).to_result()
    }

    pub fn get_frequency() -> Result<Hz, ErrorCode> {
        S::command(DRIVER_NUM, command::FREQUENCY, 0, 0)
            .to_result()
            .map(Hz)
    }

    pub fn sleep_for<T: Convert>(time: T) -> Result<(), ErrorCode> {
        let freq = Self::get_frequency()?;
        let ticks = time.to_ticks(freq);

        let called: Cell<Option<(u32, u32)>> = Cell::new(None);
        share::scope(|subscribe| {
            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::CALLBACK }>(subscribe, &called)?;

            S::command(DRIVER_NUM, command::SET_RELATIVE, ticks.0, 0)
                .to_result()
                .map(|_when: u32| ())?;

            loop {
                S::yield_wait();
                if let Some((_when, _ref)) = called.get() {
                    return Ok(());
                }
            }
        })
    }
}

pub struct Timer<S: Syscalls, C: platform::subscribe::Config = DefaultConfig> {
    num_notifications: u32,
    clock_frequency: Hz,
    _marker_s: PhantomData<S>,
    _marker_c: PhantomData<C>,
}

impl<S: Syscalls, C: platform::subscribe::Config> Default for Timer<S, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls, C: platform::subscribe::Config> Timer<S, C> {
    pub fn new() -> Self {
        let num_notifications = Alarm::<S, C>::driver_check().unwrap_or_default();
        let clock_frequency = Alarm::<S, C>::get_frequency().unwrap();

        Self {
            num_notifications,
            clock_frequency,
            _marker_s: PhantomData,
            _marker_c: PhantomData,
        }
    }

    /// Returns the number of notifications supported per process
    pub fn num_notifications(&self) -> u32 {
        self.num_notifications
    }

    /// Returns the clock frequency of the timer
    pub fn clock_frequency(&self) -> Hz {
        self.clock_frequency
    }

    /// Returns the current counter tick value
    pub fn get_current_clock(&self) -> TockResult<ClockValue> {
        let ticks = S::command(DRIVER_NUM, command::TIME, 0, 0).to_result::<u32, ErrorCode>()?;

        Ok(ClockValue {
            num_ticks: ticks as usize,
            clock_frequency: self.clock_frequency(),
        })
    }

    /// Stops the currently active alarm
    pub fn stop_alarm(&mut self) -> TockResult<()> {
        S::command(DRIVER_NUM, command::STOP, 0, 0).to_result::<u32, ErrorCode>()?;

        Ok(())
    }

    pub fn sleep<T: Convert>(&self, time: T) -> TockResult<()> {
        Alarm::<S, C>::sleep_for(time)?;

        Ok(())

        // I don't think we need to stop the alarm anymore after the upcall has been called by the subscription
        /*
        match self.stop_alarm() {
            Ok(_) | Err(TockError::Command(ErrorCode::Already)) => Ok(()),
            Err(e) => Err(e),
        } */
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ClockValue {
    num_ticks: usize,
    clock_frequency: Hz,
}

impl ClockValue {
    pub const fn new(num_ticks: usize, clock_hz: Hz) -> ClockValue {
        ClockValue {
            num_ticks,
            clock_frequency: clock_hz,
        }
    }

    pub fn num_ticks(&self) -> usize {
        self.num_ticks
    }

    // Computes (value * factor) / divisor, even when value * factor >= isize::MAX.
    fn scale_int(value: usize, factor: usize, divisor: usize) -> usize {
        // As long as isize is not i64, this should be fine. If not, this is an alternative:
        // factor * (value / divisor) + ((value % divisor) * factor) / divisor
        ((value as u64 * factor as u64) / divisor as u64) as usize
    }

    pub fn ms(&self) -> usize {
        ClockValue::scale_int(self.num_ticks, 1000, self.clock_frequency.0 as usize)
    }

    pub fn ms_f64(&self) -> f64 {
        1000.0 * (self.num_ticks as f64) / (self.clock_frequency.0 as f64)
    }

    pub fn wrapping_add(self, duration: Duration) -> ClockValue {
        // This is a precision preserving formula for scaling an isize.
        let duration_ticks = ClockValue::scale_int(
            duration.as_millis() as usize,
            self.clock_frequency.0 as usize,
            1000,
        );
        ClockValue {
            num_ticks: self.num_ticks.wrapping_add(duration_ticks),
            clock_frequency: self.clock_frequency,
        }
    }

    pub fn wrapping_sub(self, other: ClockValue) -> Option<Duration> {
        if self.clock_frequency == other.clock_frequency {
            let clock_duration = ClockValue {
                num_ticks: self.num_ticks - other.num_ticks,
                clock_frequency: self.clock_frequency,
            };
            Some(Duration::from_millis(clock_duration.ms() as u64))
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

const DRIVER_NUM: u32 = 0;

// Command IDs
#[allow(unused)]
mod command {
    pub const DRIVER_CHECK: u32 = 0;
    pub const FREQUENCY: u32 = 1;
    pub const TIME: u32 = 2;
    pub const STOP: u32 = 3;

    pub const SET_RELATIVE: u32 = 5;
    pub const SET_ABSOLUTE: u32 = 6;
}

#[allow(unused)]
mod subscribe {
    pub const CALLBACK: u32 = 0;
}
