// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

use crate::device::Error;

#[cfg(target_os = "macos")]
use nix::unistd::User;
use nix::unistd::{Gid, Uid, setgid, setuid};

#[cfg(target_os = "macos")]
pub fn get_saved_ids() -> Result<(Uid, Gid), Error> {
    // Get the user name of the sudoer
    match std::env::var("USER") {
        Ok(uname) => match User::from_name(&uname) {
            Ok(Some(user)) => {
                let uid = Uid::from_raw(uid_t::from(user.uid));
                let gid = Gid::from_raw(gid_t::from(user.gid));
                Ok((uid, gid))
            }
            Err(e) => Err(Error::DropPrivileges(format!(
                "Failed parse user; err: {e:?}"
            ))),
            Ok(None) => Err(Error::DropPrivileges("Failed to find user".to_owned())),
        },
        Err(e) => Err(Error::DropPrivileges(format!(
            "Could not get environment variable for user; err: {e:?}"
        ))),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn get_saved_ids() -> Result<(Uid, Gid), Error> {
    use libc::{getlogin, getpwnam};

    let uname = unsafe { getlogin() };
    if uname.is_null() {
        return Err(Error::DropPrivileges("NULL from getlogin".to_owned()));
    }
    let userinfo = unsafe { getpwnam(uname) };
    if userinfo.is_null() {
        return Err(Error::DropPrivileges("NULL from getpwnam".to_owned()));
    }

    // Saved group ID
    let saved_gid = unsafe { (*userinfo).pw_gid };
    // Saved user ID
    let saved_uid = unsafe { (*userinfo).pw_uid };

    Ok((Uid::from_raw(saved_uid), Gid::from_raw(saved_gid)))
}

pub fn drop_privileges() -> Result<(), Error> {
    let (saved_uid, saved_gid) = get_saved_ids()?;

    // Set real and effective user/group ID
    setgid(saved_gid)
        .and_then(|_| setuid(saved_uid))
        .map_err(|e| e.to_string())
        .map_err(Error::DropPrivileges)?;

    // Validate that we can't get sudo back again
    if setgid(Gid::from_raw(0)).is_ok() || setuid(Uid::from_raw(0)).is_ok() {
        Err(Error::DropPrivileges(
            "Failed to permanently drop privileges".to_owned(),
        ))
    } else {
        Ok(())
    }
}
