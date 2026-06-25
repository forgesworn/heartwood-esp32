//! Global heap allocator for the data plane.
//!
//! The lx106 has no `alloc` without an allocator; the inline `ENCRYPTED_REQUEST`
//! (0x10) sign path (NIP-44 buffers, JSON) needs one. `embedded-alloc` is backed
//! by `critical-section`, whose impl we provide over the xtensa interrupt
//! enable/disable primitives.

use core::mem::MaybeUninit;

use embedded_alloc::LlffHeap as Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Heap size — sized for the eventual NIP-44 + JSON + signing-set peak (~18 KB
/// per the scoping), with headroom in the lx106's ~80 KB DRAM.
const HEAP_SIZE: usize = 24 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

/// Initialise the heap. Must be called once, before any allocation.
pub fn init() {
    unsafe {
        HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
    }
}

// critical-section impl over the xtensa interrupt mask. Single-core: the
// firmware never enables interrupts, so acquire/release is effectively a no-op,
// but a correct impl keeps the allocator sound if interrupts are added later.
struct XtensaSingleCore;
critical_section::set_impl!(XtensaSingleCore);

unsafe impl critical_section::Impl for XtensaSingleCore {
    unsafe fn acquire() -> critical_section::RawRestoreState {
        xtensa_lx::interrupt::disable()
    }
    unsafe fn release(token: critical_section::RawRestoreState) {
        xtensa_lx::interrupt::enable_mask(token);
    }
}
