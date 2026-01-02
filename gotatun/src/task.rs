// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::pin::Pin;
use tokio::task::JoinHandle;
use tracing::Instrument;

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
    handle: Option<JoinHandle<()>>,
    span: tracing::Span,
}

pub trait TaskOutput: Sized + Send + 'static {
    fn handle(self, task_name: &'static str) {
        tracing::debug!("task {task_name:?} exited");
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
        // Set task parent to None to avoid nesting tracing spans
        let span = tracing::info_span!(parent: None, "Task", name = name);
        let handle = tokio::spawn(
            async move {
                tracing::info!("Task started");
                let output = fut.await;
                TaskOutput::handle(output, name);
            }
            .instrument(span.clone()),
        );

        Task {
            name,
            handle: Some(handle),
            span,
        }
    }
}

impl Future for Task {
    type Output = <JoinHandle<()> as Future>::Output;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.handle
            .as_mut()
            .map(Pin::new)
            .expect("Handle is Some until task is stopped or dropped")
            .poll(cx)
    }
}

impl Task {
    #[cfg(feature = "device")]
    pub async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            match handle.await {
                Err(e) if e.is_panic() => {
                    tracing::error!(parent: &self.span, "task {} panicked: {e:#?}", self.name);
                }
                _ => {
                    tracing::debug!(parent: &self.span, "stopped task {}", self.name);
                }
            }
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            tracing::debug!(parent: &self.span, "dropped task {}", self.name);

            // Note that the task future isn't dropped when calling abort.
            // It is dropped by the tokio runtime at some point in the future.
            // Prefer calling `Task::stop` for tasks that need to be promptly cleaned up.
            handle.abort();
        }
    }
}
