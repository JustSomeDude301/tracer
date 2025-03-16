use std::io::Read;
use std::os::fd::AsRawFd;
use aya::maps::RingBuf;
use aya::programs::KProbe;
use log::{error, info};
#[rustfmt::skip]
use log::warn;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tracer_common::TcpConnect;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tracer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = ebpf.program_mut("tracer").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    tokio::spawn(
        async move {
            let mut ring_buf = RingBuf::try_from(ebpf.map_mut("OUTBOUND_TCP").unwrap()).unwrap();

            let poll = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();

            loop {
                let guard = poll.readable().await;

                match guard {
                    Ok(mut guard) => {
                        while let Some(event) = ring_buf.next() {
                            let event = unsafe { &*event.as_ptr().cast::<TcpConnect>() };

                            match event {
                                TcpConnect::Ipv4 { .. } => {
                                    info!("Received outbound ipv4 tcp event in userspace");
                                }
                                TcpConnect::Ipv6 { .. } => {
                                    info!("Received outbound ipv6 tcp event in userspace");
                                }
                            }
                        }

                        guard.clear_ready();
                    }
                    Err(err) => {
                        error!("error reading from eBPF event: {}", err);
                    }
                }

            }
        }
    );

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
