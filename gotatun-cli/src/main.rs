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

// Common imports that are used on both platforms

// Unix implementation
#[cfg(unix)]
mod unix;

// Windows implementation
#[cfg(windows)]
mod windows;

#[cfg(unix)]
fn main() {
    unix::main();
}

#[cfg(windows)]
fn main() {
    windows::main();
}

#[cfg(not(any(unix, windows)))]
fn main() {
    unimplemented!("GotaTun CLI is not supported on this platform");
}
