//! The alarm driver
//!
//! # Example
//! ```
//! // Wait for timeout
//! Alarm::sleep(Alarm::Milliseconds(2500));
//! ```
//!
//! Adapted from the [libtock-rs](https://github.com/tock/libtock-rs/blob/master/apis/alarm/src/lib.rs) alarm driver interface

use crate::result::{FlexUnwrap, OtherError, TockError, TockResult};
use crate::util::Util;
use core::cell::Cell;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub};
use libtock_platform as platform;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use platform::subscribe::OneId;
use platform::Upcall;

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

pub struct WithCallback<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)> {
    callback: CB,
    clock_frequency: Hz,
    _marker_s: PhantomData<S>,
    _marker_c: PhantomData<C>,
}

pub fn with_callback<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)>(
    callback: CB,
) -> TimerUpcallConsumer<S, C, CB> {
    TimerUpcallConsumer {
        data: WithCallback {
            callback,
            clock_frequency: Hz(0),
            _marker_s: PhantomData,
            _marker_c: PhantomData,
        },
    }
}

pub struct TimerUpcallConsumer<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)> {
    data: WithCallback<S, C, CB>,
}

impl<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)>
    Upcall<OneId<DRIVER_NUM, { subscribe::CALLBACK }>> for TimerUpcallConsumer<S, C, CB>
{
    fn upcall(&self, clock_value: u32, _: u32, _: u32) {
        (self.data.callback)(ClockValue::new(
            clock_value as isize,
            self.data.clock_frequency,
        ))
    }
}

impl<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)>
    TimerUpcallConsumer<S, C, CB>
{
    /// Initializes the data of the containing [WithCallback], i.e. number of notifications, clock frequency, and registers the
    /// subscription for the timer upcall.
    pub fn init(&mut self) -> TockResult<Timer<S, C>> {
        // alarm driver only returns success as only a single concurrent timer is supported
        let num_notifications = S::command(DRIVER_NUM, command::DRIVER_CHECK, 0, 0)
            .to_result::<(), ErrorCode>()
            .map(|_| 1)?;

        let clock_frequency =
            S::command(DRIVER_NUM, command::FREQUENCY, 0, 0).to_result::<u32, ErrorCode>()?;

        if clock_frequency == 0 {
            return Err(OtherError::TimerDriverErroneousClockFrequency.into());
        }

        let clock_frequency = Hz(clock_frequency);

        // register the upcall for the timer
        share::scope(|handle| {
            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::CALLBACK }>(handle, self)?;

            Ok::<(), ErrorCode>(())
        })?;

        Ok(Timer {
            num_notifications,
            clock_frequency,
            _marker_c: PhantomData,
            _marker_s: PhantomData,
        })
    }
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

    pub fn sleep(duration: Duration<isize>) -> TockResult<()> {
        let expired = Cell::new(false);
        let mut with_callback = with_callback::<S, C, _>(|_| expired.set(true));

        let mut timer = with_callback.init().flex_unwrap();
        timer.set_alarm(duration).flex_unwrap();

        Util::<S>::yieldk_for(|| expired.get());

        match timer.stop_alarm() {
            Ok(_) | Err(TockError::Command(ErrorCode::Already)) => Ok(()),
            Err(e) => Err(e),
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
            num_ticks: ticks as isize,
            clock_frequency: self.clock_frequency(),
        })
    }

    /// Stops the currently active alarm
    pub fn stop_alarm(&mut self) -> TockResult<()> {
        S::unsubscribe(DRIVER_NUM, subscribe::CALLBACK);
        S::command(DRIVER_NUM, command::STOP, 0, 0).to_result::<u32, ErrorCode>()?;

        Ok(())
    }

    pub fn set_alarm(&mut self, duration: Duration<isize>) -> TockResult<()> {
        let now = self.get_current_clock()?;
        let freq = self.clock_frequency;
        let duration_ms = duration.ms() as usize;

        let ticks = match duration_ms.checked_mul(freq.0 as usize) {
            Some(x) => x / 1000,
            None => {
                // Divide the largest of the two operands by 1000, to improve precision of the
                // result.
                if duration_ms > freq.0 as usize {
                    match (duration_ms / 1000).checked_mul(freq.0 as usize) {
                        Some(y) => y,
                        None => return Err(OtherError::TimerDriverDurationOutOfRange.into()),
                    }
                } else {
                    match (freq.0 as usize / 1000).checked_mul(duration_ms) {
                        Some(y) => y,
                        None => return Err(OtherError::TimerDriverDurationOutOfRange.into()),
                    }
                }
            }
        };

        let alarm_instant = now.num_ticks() as usize + ticks;

        S::command(DRIVER_NUM, command::SET_RELATIVE, alarm_instant as u32, 0)
            .to_result::<u32, ErrorCode>()?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ClockValue {
    num_ticks: isize,
    clock_frequency: Hz,
}

impl ClockValue {
    pub const fn new(num_ticks: isize, clock_hz: Hz) -> ClockValue {
        ClockValue {
            num_ticks,
            clock_frequency: clock_hz,
        }
    }

    pub fn num_ticks(&self) -> isize {
        self.num_ticks
    }

    // Computes (value * factor) / divisor, even when value * factor >= isize::MAX.
    fn scale_int(value: isize, factor: isize, divisor: isize) -> isize {
        // As long as isize is not i64, this should be fine. If not, this is an alternative:
        // factor * (value / divisor) + ((value % divisor) * factor) / divisor
        ((value as i64 * factor as i64) / divisor as i64) as isize
    }

    pub fn ms(&self) -> isize {
        ClockValue::scale_int(self.num_ticks, 1000, self.clock_frequency.0 as isize)
    }

    pub fn ms_f64(&self) -> f64 {
        1000.0 * (self.num_ticks as f64) / (self.clock_frequency.0 as f64)
    }

    pub fn wrapping_add(self, duration: Duration<isize>) -> ClockValue {
        // This is a precision preserving formula for scaling an isize.
        let duration_ticks =
            ClockValue::scale_int(duration.ms, self.clock_frequency.0 as isize, 1000);
        ClockValue {
            num_ticks: self.num_ticks.wrapping_add(duration_ticks),
            clock_frequency: self.clock_frequency,
        }
    }

    pub fn wrapping_sub(self, other: ClockValue) -> Option<Duration<isize>> {
        if self.clock_frequency == other.clock_frequency {
            let clock_duration = ClockValue {
                num_ticks: self.num_ticks - other.num_ticks,
                clock_frequency: self.clock_frequency,
            };
            Some(Duration::from_ms(clock_duration.ms()))
        } else {
            None
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration<T> {
    ms: T,
}

impl<T> Duration<T> {
    pub const fn from_ms(ms: T) -> Duration<T> {
        Duration { ms }
    }
}

impl<T> Duration<T>
where
    T: Copy,
{
    pub fn ms(&self) -> T {
        self.ms
    }
}

impl<T> Sub for Duration<T>
where
    T: Sub<Output = T>,
{
    type Output = Duration<T>;

    fn sub(self, other: Duration<T>) -> Duration<T> {
        Duration {
            ms: self.ms - other.ms,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Timestamp<T> {
    ms: T,
}

impl<T> Timestamp<T> {
    pub const fn from_ms(ms: T) -> Timestamp<T> {
        Timestamp { ms }
    }
}

impl<T> Timestamp<T>
where
    T: Copy,
{
    pub fn ms(&self) -> T {
        self.ms
    }
}

impl Timestamp<isize> {
    pub fn from_clock_value(value: ClockValue) -> Timestamp<isize> {
        Timestamp { ms: value.ms() }
    }
}

impl Timestamp<f64> {
    pub fn from_clock_value(value: ClockValue) -> Timestamp<f64> {
        Timestamp { ms: value.ms_f64() }
    }
}

impl<T> Sub for Timestamp<T>
where
    T: Sub<Output = T>,
{
    type Output = Duration<T>;

    fn sub(self, other: Timestamp<T>) -> Duration<T> {
        Duration::from_ms(self.ms - other.ms)
    }
}

impl<T> Add<Duration<T>> for Timestamp<T>
where
    T: Copy + Add<Output = T>,
{
    type Output = Timestamp<T>;

    fn add(self, duration: Duration<T>) -> Timestamp<T> {
        Timestamp {
            ms: self.ms + duration.ms(),
        }
    }
}

impl<T> AddAssign<Duration<T>> for Timestamp<T>
where
    T: Copy + AddAssign,
{
    fn add_assign(&mut self, duration: Duration<T>) {
        self.ms += duration.ms();
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
