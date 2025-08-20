use boringtun::packet::{IpNextProtocol, Ipv4, Ipv4Header, Packet};
use boringtun::udp::channel::Ipv4Fragments;
use bytes::BytesMut;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::net::Ipv4Addr;
use zerocopy::FromBytes;

fn fragment_ipv4_packet(
    identification: u16,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    payload: &[u8],
    mtu: usize,
) -> Vec<Packet<Ipv4>> {
    let ipv4_header_len = 20;
    let max_payload_per_fragment = ((mtu - ipv4_header_len) / 8) * 8; // must be multiple of 8
    let payload_chunks = payload.chunks_exact(max_payload_per_fragment);
    let last_payload = payload_chunks.remainder();
    assert!(!last_payload.is_empty());
    let last_fragment = make_single_fragment(
        identification,
        source_ip,
        destination_ip,
        ((payload.len() & max_payload_per_fragment) / 8) as u16,
        false,
        last_payload,
    );
    payload_chunks
        .zip(0..)
        .map(|(payload, i)| {
            make_single_fragment(
                identification,
                source_ip,
                destination_ip,
                (i * max_payload_per_fragment / 8) as u16,
                true,
                payload,
            )
        })
        .chain(std::iter::once(last_fragment))
        .collect()
}

fn make_single_fragment(
    identification: u16,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    offset: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Packet<Ipv4> {
    let mut buf = BytesMut::zeroed(Ipv4Header::LEN + payload.len()); // TODO: Use PacketBufPool?
    let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
    ipv4.header = Ipv4Header::new(source_ip, destination_ip, IpNextProtocol::Udp, payload);
    ipv4.header.identification = identification.into();
    let mut flags = boringtun::packet::Ipv4FlagsFragmentOffset::new();
    flags.set_more_fragments(more_fragments);
    flags.set_fragment_offset(offset);
    ipv4.header.flags_and_fragment_offset = flags;
    ipv4.payload.copy_from_slice(payload);

    Packet::from_bytes(buf)
        .try_into_ipvx()
        .unwrap()
        .unwrap_left()
}

fn bench_assemble_ipv4_fragment(c: &mut Criterion) {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let id = 42;
    let mtu = 1500;
    let payload = vec![0u8; 4000]; // Large payload to force fragmentation
    let mut fragments = Ipv4Fragments::default();
    let frags = fragment_ipv4_packet(id, src, dst, &payload, mtu);
    // let mut packet_pool = boringtun::packet::PacketBufPool::<4096>::new(4000);

    c.bench_function("assemble_ipv4_fragment", |b| {
        b.iter(|| {
            for frag in &frags {
                // let packet = packet_pool.get();
                // black_box(
                //     fragments.assemble_ipv4_fragment(black_box(packet.copy_from_packet(frag))),
                // );
                black_box(fragments.assemble_ipv4_fragment(black_box(Packet::copy_from(frag))));
            }
        })
    });
}

criterion_group!(benches, bench_assemble_ipv4_fragment);
criterion_main!(benches);
