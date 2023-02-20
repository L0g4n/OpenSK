// Copyright 2020 Google LLC
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

#![no_main]
#![no_std]

extern crate lang_items;

use core::fmt::Write;
use libtock_buttons::{ButtonListener, Buttons};
use libtock_console::Console;

use libtock_platform::{share, Syscalls};
use libtock_runtime::{set_main, stack_size, TockSyscalls};

stack_size! {0x800}
set_main! {main}

fn main() {
    let mut writer = Console::<TockSyscalls>::writer();

    let listener = ButtonListener(|btn, state| {
        writeln!(
            Console::<TockSyscalls>::writer(),
            "Button {btn} is {:?}",
            state
        )
        .ok()
        .unwrap();
    });

    if let Ok(btns_cnt) = Buttons::<TockSyscalls>::count() {
        writeln!(writer, "{btns_cnt} buttons are available!")
            .ok()
            .unwrap();

        if let Ok(()) =
            share::scope(|sub| Buttons::<TockSyscalls>::register_listener(&listener, sub))
        {
            loop {
                TockSyscalls::yield_wait();
            }
        }
    }
}
