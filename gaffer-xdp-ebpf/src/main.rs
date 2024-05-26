#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, memcpy, programs::XdpContext};
use aya_log_ebpf::{info, WriteToBuf};
use core::{hash::Hasher, mem};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[xdp]
pub fn gaffer_xdp(ctx: XdpContext) -> u32 {
    match hash_responder(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn hash_responder(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr_ptr = ptr_at(&ctx, 0)?;
    let mut ethhdr: EthHdr = unsafe { *ethhdr_ptr };

    match ethhdr.ether_type {
        EtherType::Loop => {}
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr_ptr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let mut ipv4hdr: Ipv4Hdr = unsafe { *ipv4hdr_ptr };

    if ipv4hdr.proto == IpProto::Tcp {
        info!(&ctx, "tcp packet received, ignored!");
        return Ok(xdp_action::XDP_PASS); // dont care about tcp packets, let them through
    }

    let source_addr = u32::from_be(ipv4hdr.src_addr);

    let udphdr_ptr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let mut udphdr: UdpHdr = unsafe { *udphdr_ptr };

    let dest_port = u16::from_be(udphdr.dest);

    if dest_port != 32001 {
        // info!(
        //     &ctx,
        //     "IGNORING OTHER: {} from {}:{}",
        //     dest_port,
        //     source_addr,
        //     u16::from_be(udphdr.source),
        // );
        return Ok(xdp_action::XDP_PASS);
    }

    let data_ptr: *mut u8 = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;
    let data_len = ctx.data_end() - data_ptr as usize;

    if data_len != 100 {
        return Ok(xdp_action::XDP_PASS);
    }

    let hasher_data = unsafe { core::slice::from_raw_parts(data_ptr, 100) };

    let mut hasher = fnv::FnvHasher::default();
    hasher.write(hasher_data);
    let output = hasher.finish().to_le_bytes().as_mut_ptr();

    // response creation
    core::mem::swap(&mut udphdr.dest, &mut udphdr.source);
    udphdr.len = ((mem::size_of::<UdpHdr>() + 8) as u16).to_be();
    udphdr.check = 0;

    core::mem::swap(&mut ipv4hdr.src_addr, &mut ipv4hdr.dst_addr);
    ipv4hdr.tot_len = ((mem::size_of::<Ipv4Hdr>() + mem::size_of::<UdpHdr>() + 8) as u16).to_be();

    let ipv4hdr_slice = unsafe {
        core::slice::from_raw_parts((&ipv4hdr as *const Ipv4Hdr) as *const u8, Ipv4Hdr::LEN)
    };
    ipv4hdr.check = unsafe { calculate_checksum(ipv4hdr_slice, 5) }.to_be();

    unsafe {
        let mut swapper = [0_u8; 6];
        memcpy(swapper.as_mut_ptr(), ethhdr.dst_addr.as_mut_ptr(), 6);
        memcpy(
            ethhdr.dst_addr.as_mut_ptr(),
            ethhdr.src_addr.as_mut_ptr(),
            6,
        );
        memcpy(ethhdr.src_addr.as_mut_ptr(), swapper.as_mut_ptr(), 6);
    }

    unsafe {
        *udphdr_ptr = udphdr;
        *ipv4hdr_ptr = ipv4hdr;
        *ethhdr_ptr = ethhdr;
        memcpy(data_ptr, output, 8);
    }

    let dest_ip = u32::from_be(unsafe { (*ipv4hdr_ptr).dst_addr });
    let dest_port = u16::from_be(unsafe { (*udphdr_ptr).dest });

    // info!(
    //     &ctx,
    //     "receiving from {}:{}, sending it back to {}:{}",
    //     source_addr,
    //     dest_port,
    //     dest_ip,
    //     dest_port
    // );

    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
unsafe fn calculate_checksum(data: &[u8], skipword: usize) -> u16 {
    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;

    while cur_data.len() >= 2 {
        if i != skipword {
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }

        cur_data = &cur_data[2..];
        i += 1;
    }

    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    let sum = !sum as u16;

    sum
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
