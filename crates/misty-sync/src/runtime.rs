// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A minimal executor, so this crate's tests need no async runtime.
//!
//! [`Transport::request`](crate::Transport::request) is an `async fn`, so
//! something has to drive the futures. Pulling `tokio` in as a test dependency
//! would work natively and not at all on `wasm32-unknown-unknown`, and the
//! protocol tests are supposed to run on every target.
//!
//! So: thirty lines of `std`. It parks the thread between polls rather than
//! spinning, which makes it correct rather than merely adequate, and it has no
//! timer — [`TokioSleeper`](crate::TokioSleeper) and
//! [`NativeTransport`](crate::NativeTransport) both need a real runtime and will
//! not make progress here. With [`MockTransport`](crate::MockTransport) and
//! [`MockSleeper`](crate::MockSleeper), which never yield, it is exactly enough.
//!
//! Absent on wasm, where `std::thread::park` has nothing to park: a browser
//! caller uses `wasm_bindgen_futures::spawn_local`.

#![cfg(not(target_arch = "wasm32"))]

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::task::{Wake, Waker};

/// Wakes by unparking the thread that is blocked in [`block_on`].
struct ThreadWaker(std::thread::Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Drives `future` to completion on the current thread.
///
/// ```
/// # use misty_sync::runtime::block_on;
/// assert_eq!(block_on(async { 1 + 1 }), 2);
/// ```
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            // `unpark` before `park` leaves a token behind, so a wake that
            // arrives between the poll and here does not lose the wakeup.
            Poll::Pending => std::thread::park(),
        }
    }
}
