// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use std::time::Duration;

use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_gettime};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
const CLOCK_ID: ClockId = ClockId::CLOCK_MONOTONIC;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
const CLOCK_ID: ClockId = ClockId::CLOCK_BOOTTIME;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant {
    t: TimeSpec,
}

impl Instant {
    pub(crate) fn now() -> Self {
        // std::time::Instant unwraps as well, so feel safe doing so here
        let t = clock_gettime(CLOCK_ID).unwrap();
        Self { t }
    }

    pub(crate) fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        const NANOSECOND: nix::libc::c_long = 1_000_000_000;
        let (tv_sec, tv_nsec) = if self.t.tv_nsec() < earlier.t.tv_nsec() {
            (
                self.t.tv_sec() - earlier.t.tv_sec() - 1,
                self.t.tv_nsec() - earlier.t.tv_nsec() + NANOSECOND,
            )
        } else {
            (
                self.t.tv_sec() - earlier.t.tv_sec(),
                self.t.tv_nsec() - earlier.t.tv_nsec(),
            )
        };

        if tv_sec < 0 {
            None
        } else {
            Some(Duration::new(tv_sec as _, tv_nsec as _))
        }
    }

    pub(crate) fn checked_add(&self, duration: Duration) -> Option<Instant> {
        const NANOSECOND: nix::libc::c_long = 1_000_000_000;

        let add_nsec = duration.subsec_nanos() as nix::libc::c_long;
        let cur_nsec = self.t.tv_nsec();

        // `tv_nsec` from `clock_gettime` is in `[0, NANOSECOND)` and `subsec_nanos` is
        // below `NANOSECOND`, so the normalized result is too. Compare against the
        // complement rather than adding the two: `tv_nsec` is a `c_long`, which is only
        // 32 bits wide on some targets, and their sum does not always fit in that.
        let (carry, nsec) = if cur_nsec >= NANOSECOND - add_nsec {
            (1, cur_nsec - (NANOSECOND - add_nsec))
        } else {
            (0, cur_nsec + add_nsec)
        };

        // `time_t` is also only 32 bits wide on some targets. Both of these reject a
        // result it cannot represent, which takes an uptime far beyond anything a
        // WireGuard timer waits for.
        let add_sec: nix::libc::time_t = duration.as_secs().try_into().ok()?;
        let sec = self.t.tv_sec().checked_add(add_sec)?.checked_add(carry)?;

        Some(Instant {
            t: TimeSpec::new(sec, nsec),
        })
    }
}
