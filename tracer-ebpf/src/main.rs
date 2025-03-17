#![no_std]
#![no_main]

#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[rustfmt::skip]
mod binding;

use crate::binding::{sock, sock_common};

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use aya_log_ebpf::debug;
use tracer_common::TcpConnect;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const LOOPBACK_V4: u32 = 0x7F000001;

const LOOPBACK_V6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[map]
static OUTBOUND_TCP: RingBuf = RingBuf::with_byte_size(4096 * TcpConnect::LEN as u32, 0);

#[kprobe]
pub fn tracer(ctx: ProbeContext) -> u32 {
    match try_tracer(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline]
fn submit(event: TcpConnect) {
    if let Some(mut buf) = OUTBOUND_TCP.reserve::<TcpConnect>(0) {
        unsafe { *buf.as_mut_ptr() = event };
        buf.submit(0);
    }
}

fn try_tracer(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)
    }?;

    match sk_common.skc_family {
        AF_INET => {
            let src_addr = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
            });
            let dest_addr = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
            });

            if src_addr != LOOPBACK_V4 && dest_addr != LOOPBACK_V4 {
                debug!(
                    &ctx,
                    "AF_INET src address: {:i}, dest address: {:i}",
                    src_addr,
                    dest_addr,
                );

                submit(TcpConnect::Ipv4(src_addr, dest_addr));
            };

            Ok(0)
        }
        AF_INET6 => {
            let (src_addr, dest_addr) = unsafe {
                (sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
                 sk_common.skc_v6_daddr.in6_u.u6_addr8)
            };

            if src_addr != LOOPBACK_V6 && dest_addr != LOOPBACK_V6 {
                debug!(
                    &ctx,
                    "AF_INET6 src addr: {:i}, dest addr: {:i}",
                    src_addr,
                    dest_addr
                );

                submit(TcpConnect::Ipv6(src_addr, dest_addr));
            };

            Ok(0)
        }
        _ => Ok(0)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
