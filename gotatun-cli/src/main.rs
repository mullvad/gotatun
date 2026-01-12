// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

// Common imports that are used on both platforms

// Unix implementation
#[cfg(unix)]
mod unix;

#[cfg(unix)]
fn main() {
    unix::main();
}

#[cfg(not(unix))]
fn main() {
    // Empty main function for Windows
    unimplemented!("GotaTun CLI is not supported on Windows");
}
