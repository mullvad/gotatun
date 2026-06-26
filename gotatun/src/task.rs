// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0
#![cfg(any(feature = "device", feature = "tun"))]

use futures::executor::block_on;
use std::pin::Pin;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// A wrapper around [`JoinHandle`] that.
/// - Aborts the task on Drop.
/// - If the task returns an `Err`, logs it.
pub struct Task {
    name: &'static str,

    /// [`JoinHandle`] for the tokio task.
    ///
    /// INVARIANT: This will be `Some` until either of:
    /// - Self is dropped.
    /// - [`Self::stop`] is called.
    handle: Option<std::thread::JoinHandle<Option<()>>>,

    output: oneshot::Receiver<()>,

    ct: CancellationToken,
}

pub trait TaskOutput: Sized + Send + 'static {
    fn handle(self, task_name: &'static str) {
        tracing::trace!("task {task_name:?} exited");
    }
}

impl TaskOutput for () {}

impl<T, E> TaskOutput for Result<T, E>
where
    Self: Send + 'static,
    E: std::fmt::Debug,
{
    fn handle(self, task_name: &'static str) {
        match self {
            Ok(..) => ().handle(task_name),
            Err(e) => tracing::error!("task {task_name:?} errored: {e:?}"),
        }
    }
}

impl Task {
    #[track_caller]
    pub fn spawn<Fut, O>(name: &'static str, fut: Fut) -> Self
    where
        Fut: Future<Output = O> + Send + 'static,
        O: TaskOutput,
    {
        let ct = CancellationToken::new();
        let child_ct = ct.child_token();
        let rt_handle = tokio::runtime::Handle::current();
        let (output_tx, output_rx) = oneshot::channel();
        let handle = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let _runtime = rt_handle.enter();
                block_on(child_ct.run_until_cancelled_owned(async move {
                    let output = fut.await;
                    TaskOutput::handle(output, name);
                    _ = output_tx.send(());
                }))
            })
            .unwrap();

        Task {
            name,
            handle: Some(handle),
            ct,
            output: output_rx,
        }
    }

    #[cfg(feature = "device")]
    pub async fn stop(mut self) {
        self.ct.cancel();
        if let Some(handle) = self.handle.take() {
            let result = tokio::task::block_in_place(|| handle.join());
            match result {
                Err(e) => {
                    tracing::error!("task {} panicked: {e:#?}", self.name);
                }
                _ => {
                    tracing::trace!("stopped task {}", self.name);
                }
            }
        }
    }
}

impl Future for Task {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.output).poll(cx).map(|_| ())
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(_handle) = self.handle.take() {
            tracing::trace!("dropped task {}", self.name);

            // Note that the task future isn't stopped immediately when cancelled.
            // It is stopped by the tokio runtime at some point in the future.
            // Prefer calling `Task::stop` for tasks that need to be promptly cleaned up.
            self.ct.cancel();
        }
    }
}
