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

#![cfg_attr(not(feature = "std"), no_std)]
#![no_main]

extern crate alloc;
extern crate arrayref;
extern crate byteorder;
#[cfg(feature = "std")]
extern crate core;
extern crate lang_items;

#[cfg(feature = "debug_ctap")]
use core::convert::TryFrom;
use core::convert::TryInto;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use ctap2::api::connection::{HidConnection, SendOrRecvStatus};
#[cfg(feature = "debug_ctap")]
use ctap2::clock::CtapClock;
use ctap2::clock::{new_clock, Clock, ClockInt, KEEPALIVE_DELAY, KEEPALIVE_DELAY_MS};
use ctap2::ctap::hid::HidPacketIterator;
#[cfg(feature = "with_ctap1")]
use ctap2::env::tock::blink_leds;
use ctap2::env::tock::{switch_off_leds, wink_leds, TockEnv};
use ctap2::Transport;
#[cfg(feature = "debug_ctap")]
use embedded_time::duration::Microseconds;
use embedded_time::duration::Milliseconds;
#[cfg(feature = "with_ctap1")]
use libtock_buttons::Buttons;
#[cfg(feature = "debug_ctap")]
use libtock_console::Console;
#[cfg(feature = "debug_ctap")]
use libtock_console::ConsoleWriter;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer::Duration;
use libtock_drivers::usb_ctap_hid;
#[cfg(not(feature = "std"))]
use libtock_runtime::{set_main, stack_size, TockSyscalls};
#[cfg(feature = "std")]
use libtock_unittest::fake;
use usb_ctap_hid::UsbEndpoint;

#[cfg(not(feature = "std"))]
stack_size! {0x4000}
#[cfg(not(feature = "std"))]
set_main! {main}

const SEND_TIMEOUT: Milliseconds<ClockInt> = Milliseconds(1000);
const KEEPALIVE_DELAY_TOCK: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY_MS as isize);

#[cfg(not(feature = "vendor_hid"))]
const NUM_ENDPOINTS: usize = 1;
#[cfg(feature = "vendor_hid")]
const NUM_ENDPOINTS: usize = 2;

// The reply/replies that are queued for each endpoint.
struct EndpointReply {
    endpoint: UsbEndpoint,
    transport: Transport,
    reply: HidPacketIterator,
}

#[cfg(feature = "std")]
type SyscallImplementation = fake::Syscalls;
#[cfg(not(feature = "std"))]
type SyscallImplementation = TockSyscalls;

impl EndpointReply {
    pub fn new(endpoint: UsbEndpoint) -> Self {
        EndpointReply {
            endpoint,
            transport: match endpoint {
                UsbEndpoint::MainHid => Transport::MainHid,
                #[cfg(feature = "vendor_hid")]
                UsbEndpoint::VendorHid => Transport::VendorHid,
            },
            reply: HidPacketIterator::none(),
        }
    }
}

// A single packet to send.
struct SendPacket {
    transport: Transport,
    packet: [u8; 64],
}

struct EndpointReplies {
    replies: [EndpointReply; NUM_ENDPOINTS],
}

impl EndpointReplies {
    pub fn new() -> Self {
        EndpointReplies {
            replies: [
                EndpointReply::new(UsbEndpoint::MainHid),
                #[cfg(feature = "vendor_hid")]
                EndpointReply::new(UsbEndpoint::VendorHid),
            ],
        }
    }

    pub fn next_packet(&mut self) -> Option<SendPacket> {
        for ep in self.replies.iter_mut() {
            if let Some(packet) = ep.reply.next() {
                return Some(SendPacket {
                    transport: ep.transport,
                    packet,
                });
            }
        }
        None
    }
}

fn main() {
    let clock = new_clock();
    #[cfg(feature = "debug_ctap")]
    let mut writer = Console::<SyscallImplementation>::writer();

    #[cfg(feature = "debug_ctap")]
    {
        writeln!(writer, "Hello world from ctap2!").ok().unwrap();
    }

    // Setup USB driver.
    if !usb_ctap_hid::UsbCtapHid::<SyscallImplementation>::setup() {
        panic!("Cannot setup USB driver");
    }

    let boot_time = clock.try_now().unwrap();
    let env = TockEnv::<SyscallImplementation>::new();
    let mut ctap = ctap2::Ctap::new(env, boot_time);

    let mut led_counter = 0;
    let mut last_led_increment = boot_time;

    let mut replies = EndpointReplies::new();

    // Main loop. If CTAP1 is used, we register button presses for U2F while receiving and waiting.
    // The way TockOS and apps currently interact, callbacks need a yield syscall to execute,
    // making consistent blinking patterns and sending keepalives harder.

    #[cfg(feature = "debug_ctap")]
    writeln!(writer, "Entering main ctap loop").unwrap();
    loop {
        // Create the button callback, used for CTAP1.
        // #[cfg(feature = "with_ctap1")]
        // let button_touched = Cell::new(false);
        // #[cfg(feature = "with_ctap1")]
        // let buttons_listener = ButtonListener(|_button_num, state| {
        //     match state {
        //         ButtonState::Pressed => button_touched.set(true),
        //         ButtonState::Released => (),
        //     };
        // });
        // #[cfg(feature = "with_ctap1")]
        // share::scope(|subscribe| {
        //     Buttons::<SyscallImplementation>::register_listener(&buttons_listener, subscribe)
        // })
        // .ok()
        // .unwrap();
        #[cfg(feature = "with_ctap1")]
        let num_buttons = Buttons::<SyscallImplementation>::count().ok().unwrap();
        // // At the moment, all buttons are accepted. You can customize your setup here.
        // #[cfg(feature = "with_ctap1")]
        // for n in 0..num_buttons {
        //     Buttons::<SyscallImplementation>::enable_interrupts(n)
        //         .ok()
        //         .unwrap();
        // }

        // Variable for use in both the send_and_maybe_recv and recv cases.
        let mut usb_endpoint: Option<UsbEndpoint> = None;
        let mut pkt_request = [0; 64];

        if let Some(mut packet) = replies.next_packet() {
            // send and receive.
            let hid_connection = packet.transport.hid_connection(ctap.env());
            match hid_connection.send_and_maybe_recv(&mut packet.packet, SEND_TIMEOUT) {
                Ok(SendOrRecvStatus::Timeout) => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice::<SyscallImplementation>(
                        "Sending packet timed out",
                        &clock,
                        &mut writer,
                    );
                    // TODO: reset the ctap_hid state.
                    // Since sending the packet timed out, we cancel this reply.
                    break;
                }
                Ok(SendOrRecvStatus::Sent) => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice::<SyscallImplementation>(
                        "Sent packet",
                        &clock,
                        &mut writer,
                    );
                }
                Ok(SendOrRecvStatus::Received(ep)) => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice::<SyscallImplementation>(
                        "Received another packet",
                        &clock,
                        &mut writer,
                    );
                    usb_endpoint = Some(ep);

                    // Copy to incoming packet to local buffer to be consistent
                    // with the receive flow.
                    pkt_request = packet.packet;
                }
                Err(_) => panic!("Error sending packet"),
            }
        } else {
            // receive
            usb_endpoint =
                match usb_ctap_hid::UsbCtapHid::<SyscallImplementation>::recv_with_timeout(
                    &mut pkt_request,
                    KEEPALIVE_DELAY_TOCK,
                )
                .flex_unwrap()
                {
                    usb_ctap_hid::SendOrRecvStatus::Received(endpoint) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice::<SyscallImplementation>(
                            "Received packet",
                            &clock,
                            &mut writer,
                        );
                        Some(endpoint)
                    }
                    usb_ctap_hid::SendOrRecvStatus::Sent => {
                        panic!("Returned transmit status on receive")
                    }
                    usb_ctap_hid::SendOrRecvStatus::Timeout => None,
                };
        }

        let now = clock.try_now().unwrap();
        #[cfg(feature = "with_ctap1")]
        {
            // check if any button has been pressed
            let button_touched = (0..num_buttons)
                .into_iter()
                .any(Buttons::<SyscallImplementation>::is_pressed);
            if button_touched {
                ctap.state().u2f_grant_user_presence(now);
            }
            // Cleanup button callbacks. We miss button presses while processing though.
            // Heavy computation mostly follows a registered touch luckily. Unregistering
            // callbacks is important to not clash with those from check_user_presence.
            // for n in 0..num_buttons {
            //     Buttons::<SyscallImplementation>::disable_interrupts(n)
            //         .ok()
            //         .unwrap();
            // }
            // Buttons::<SyscallImplementation>::unregister_listener();
        }

        // These calls are making sure that even for long inactivity, wrapping clock values
        // don't cause problems with timers.
        ctap.update_timeouts(now);

        if let Some(endpoint) = usb_endpoint {
            let transport = match endpoint {
                UsbEndpoint::MainHid => Transport::MainHid,
                #[cfg(feature = "vendor_hid")]
                UsbEndpoint::VendorHid => Transport::VendorHid,
            };
            let reply = ctap.process_hid_packet(&pkt_request, transport, now);
            if reply.has_data() {
                // Update endpoint with the reply.
                for ep in replies.replies.iter_mut() {
                    if ep.endpoint == endpoint {
                        if ep.reply.has_data() {
                            #[cfg(feature = "debug_ctap")]
                            writeln!(
                                Console::<SyscallImplementation>::writer(),
                                "Warning overwriting existing reply for endpoint {}",
                                endpoint as usize
                            )
                            .unwrap();
                        }
                        ep.reply = reply;
                        break;
                    }
                }
            }
        }

        let now = clock.try_now().unwrap();
        if let Some(wait_duration) = now.checked_duration_since(&last_led_increment) {
            let wait_duration: Milliseconds<ClockInt> = wait_duration.try_into().unwrap();
            if wait_duration > KEEPALIVE_DELAY {
                // Loops quickly when waiting for U2F user presence, so the next LED blink
                // state is only set if enough time has elapsed.
                led_counter += 1;
                last_led_increment = now;
            }
        } else {
            // This branch means the clock frequency changed. This should never happen.
            led_counter += 1;
            last_led_increment = now;
        }

        if ctap.hid().should_wink(now) {
            wink_leds::<SyscallImplementation>(led_counter);
        } else {
            #[cfg(not(feature = "with_ctap1"))]
            switch_off_leds::<SyscallImplementation>();
            #[cfg(feature = "with_ctap1")]
            if ctap.state().u2f_needs_user_presence(now) {
                // Flash the LEDs with an almost regular pattern. The inaccuracy comes from
                // delay caused by processing and sending of packets.
                blink_leds::<SyscallImplementation>(led_counter);
            } else {
                switch_off_leds::<SyscallImplementation>();
            }
        }
    }
}

#[cfg(feature = "debug_ctap")]
fn print_packet_notice<S: libtock_platform::Syscalls>(
    notice_text: &str,
    clock: &CtapClock,
    writer: &mut ConsoleWriter<S>,
) {
    let now = clock.try_now().unwrap();
    let now_us = Microseconds::<u64>::try_from(now.duration_since_epoch())
        .unwrap()
        .0;
    writeln!(
        writer,
        "{} at {}.{:06} s",
        notice_text,
        now_us / 1_000_000,
        now_us % 1_000_000
    )
    .unwrap();
}
