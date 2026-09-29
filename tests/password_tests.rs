//! Checks that a `Password` leaves no copy of its bytes behind: not in memory once
//! dropped, and not in `Debug` output.
//!
//! A test binary of its own, because it installs a global allocator that inspects
//! the one watched allocation as it is freed.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use sevenz_rust2::Password;

struct WatchingAllocator;

/// The address of the allocation to inspect when it is freed, or 0.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// Whether the watched allocation was freed, and whether it held only zeros then.
static FREED: AtomicBool = AtomicBool::new(false);
static FREED_ZEROED: AtomicBool = AtomicBool::new(false);
/// Tests run in parallel; only one may watch at a time.
static SERIAL: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for WatchingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCHED.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is still allocated for `layout.size()` bytes, all of which
            // were written by the `Password` that owned them.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            FREED_ZEROED.store(bytes.iter().all(|&b| b == 0), Ordering::SeqCst);
            FREED.store(true, Ordering::SeqCst);
            WATCHED.store(0, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchingAllocator = WatchingAllocator;

/// Drops `password` and reports whether its buffer held only zeros when freed.
fn freed_zeroed(password: Password) -> bool {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    assert!(!password.is_empty());
    FREED.store(false, Ordering::SeqCst);
    WATCHED.store(password.as_slice().as_ptr() as usize, Ordering::SeqCst);
    drop(password);
    assert!(
        FREED.load(Ordering::SeqCst),
        "the watched buffer was not freed"
    );
    FREED_ZEROED.load(Ordering::SeqCst)
}

#[test]
fn a_dropped_password_is_wiped() {
    assert!(freed_zeroed(Password::from("correct horse battery staple")));
}

#[test]
fn a_dropped_raw_password_is_wiped() {
    assert!(freed_zeroed(Password::from_raw(b"\x01\x02\x03\x04")));
}

#[test]
fn a_dropped_clone_is_wiped() {
    let original = Password::from("correct horse battery staple");
    assert!(freed_zeroed(original.clone()));
    assert!(freed_zeroed(original));
}

#[cfg(feature = "aes256")]
#[test]
fn aes_encoder_options_debug_does_not_print_the_password() {
    let options = sevenz_rust2::encoder_options::AesEncoderOptions::new("hunter2".into());
    let debug = format!("{options:?}");
    assert!(debug.contains("Password([REDACTED])"), "{debug}");
    // "hunter2" as UTF-16LE bytes, as a derived `Debug` of the inner `Vec<u8>` would print them.
    assert!(!debug.contains("104, 0, 117, 0"), "{debug}");
}
