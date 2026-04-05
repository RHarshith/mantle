#![no_std]
#![no_main]

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

#[tracepoint(name = "mantle_sched_exec")]
pub fn mantle_sched_exec(_ctx: TracePointContext) -> u32 {
    0
}

#[tracepoint(name = "mantle_sched_fork")]
pub fn mantle_sched_fork(_ctx: TracePointContext) -> u32 {
    0
}

#[tracepoint(name = "mantle_sched_exit")]
pub fn mantle_sched_exit(_ctx: TracePointContext) -> u32 {
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
