#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub enum TcpConnect {
    Ipv4(u32, u32),
    Ipv6(u128, u128),
}

impl TcpConnect {
    pub const LEN: usize = size_of::<TcpConnect>();
}
