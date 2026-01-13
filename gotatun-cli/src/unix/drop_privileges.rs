// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

use eyre::{Context, bail};

use nix::unistd::{Gid, Uid, setgid, setuid};

pub fn get_saved_ids() -> eyre::Result<(Uid, Gid)> {
    use libc::{getlogin, getpwnam};

    let uname = unsafe { getlogin() };
    if uname.is_null() {
        bail!("NULL from getlogin");
    }
    let userinfo = unsafe { getpwnam(uname) };
    if userinfo.is_null() {
        bail!("NULL from getpwnam");
    }

    // Saved group ID
    let saved_gid = unsafe { (*userinfo).pw_gid };
    // Saved user ID
    let saved_uid = unsafe { (*userinfo).pw_uid };

    Ok((Uid::from_raw(saved_uid), Gid::from_raw(saved_gid)))
}

pub fn drop_privileges() -> eyre::Result<()> {
    let (saved_uid, saved_gid) = get_saved_ids()?;

    if saved_uid.is_root() {
        tracing::warn!("Not dropping privileges as saved UID is root");
        return Ok(());
    }

    // Set real and effective user/group ID
    setgid(saved_gid)
        .and_then(|_| setuid(saved_uid))
        .context("Failed to set user/group ID")?;

    // Validate that we can't get sudo back again
    if setgid(Gid::from_raw(0)).is_ok() || setuid(Uid::from_raw(0)).is_ok() {
        bail!("Failed to permanently drop privileges");
    } else {
        Ok(())
    }
}
