//! Benchmarks for trojan protocol parsing and serialization.

use bytes::BytesMut;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use trojan_proto::{
    AddressRef, CMD_CONNECT, CMD_UDP_ASSOCIATE, HASH_LEN, HostRef, parse_request, parse_udp_packet,
    write_request_header, write_udp_packet,
};

fn sample_hash() -> [u8; HASH_LEN] {
    *b"0123456789abcdef0123456789abcdef0123456789abcdef01234567"
}

fn bench_parse_request_ipv4(c: &mut Criterion) {
    let addr = AddressRef {
        host: HostRef::Ipv4([1, 2, 3, 4]),
        port: 443,
    };
    let mut buf = BytesMut::new();
    write_request_header(&mut buf, &sample_hash(), CMD_CONNECT, &addr).unwrap();
    buf.extend_from_slice(b"hello world payload data");
    let buf = buf.freeze();

    c.bench_function("parse_request_ipv4", |b| {
        b.iter(|| parse_request(black_box(&buf)))
    });
}

fn bench_parse_request_ipv6(c: &mut Criterion) {
    let addr = AddressRef {
        host: HostRef::Ipv6([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        port: 443,
    };
    let mut buf = BytesMut::new();
    write_request_header(&mut buf, &sample_hash(), CMD_CONNECT, &addr).unwrap();
    buf.extend_from_slice(b"hello world payload data");
    let buf = buf.freeze();

    c.bench_function("parse_request_ipv6", |b| {
        b.iter(|| parse_request(black_box(&buf)))
    });
}

fn bench_parse_request_domain(c: &mut Criterion) {
    let domain = b"example.com";
    let addr = AddressRef {
        host: HostRef::Domain(domain),
        port: 443,
    };
    let mut buf = BytesMut::new();
    write_request_header(&mut buf, &sample_hash(), CMD_CONNECT, &addr).unwrap();
    buf.extend_from_slice(b"hello world payload data");
    let buf = buf.freeze();

    c.bench_function("parse_request_domain", |b| {
        b.iter(|| parse_request(black_box(&buf)))
    });
}

fn bench_parse_udp_packet_ipv4(c: &mut Criterion) {
    let addr = AddressRef {
        host: HostRef::Ipv4([8, 8, 8, 8]),
        port: 53,
    };
    let payload = b"DNS query payload here";
    let mut buf = BytesMut::new();
    write_udp_packet(&mut buf, &addr, payload).unwrap();
    let buf = buf.freeze();

    c.bench_function("parse_udp_packet_ipv4", |b| {
        b.iter(|| parse_udp_packet(black_box(&buf)))
    });
}

fn bench_parse_udp_packet_domain(c: &mut Criterion) {
    let domain = b"dns.google.com";
    let addr = AddressRef {
        host: HostRef::Domain(domain),
        port: 53,
    };
    let payload = b"DNS query payload here";
    let mut buf = BytesMut::new();
    write_udp_packet(&mut buf, &addr, payload).unwrap();
    let buf = buf.freeze();

    c.bench_function("parse_udp_packet_domain", |b| {
        b.iter(|| parse_udp_packet(black_box(&buf)))
    });
}

fn bench_write_request_header_ipv4(c: &mut Criterion) {
    let hash = sample_hash();
    let addr = AddressRef {
        host: HostRef::Ipv4([1, 2, 3, 4]),
        port: 443,
    };
    let mut buf = BytesMut::with_capacity(128);

    c.bench_function("write_request_header_ipv4", |b| {
        b.iter(|| {
            buf.clear();
            write_request_header(&mut buf, black_box(&hash), CMD_CONNECT, black_box(&addr))
        })
    });
}

fn bench_write_request_header_domain(c: &mut Criterion) {
    let hash = sample_hash();
    let domain = b"example.com";
    let addr = AddressRef {
        host: HostRef::Domain(domain),
        port: 443,
    };
    let mut buf = BytesMut::with_capacity(128);

    c.bench_function("write_request_header_domain", |b| {
        b.iter(|| {
            buf.clear();
            write_request_header(&mut buf, black_box(&hash), CMD_CONNECT, black_box(&addr))
        })
    });
}

fn bench_write_udp_packet_ipv4(c: &mut Criterion) {
    let addr = AddressRef {
        host: HostRef::Ipv4([8, 8, 8, 8]),
        port: 53,
    };
    let payload = b"DNS query payload data here for benchmark";
    let mut buf = BytesMut::with_capacity(128);

    c.bench_function("write_udp_packet_ipv4", |b| {
        b.iter(|| {
            buf.clear();
            write_udp_packet(&mut buf, black_box(&addr), black_box(payload))
        })
    });
}

fn bench_write_udp_packet_domain(c: &mut Criterion) {
    let domain = b"dns.google.com";
    let addr = AddressRef {
        host: HostRef::Domain(domain),
        port: 53,
    };
    let payload = b"DNS query payload data here for benchmark";
    let mut buf = BytesMut::with_capacity(128);

    c.bench_function("write_udp_packet_domain", |b| {
        b.iter(|| {
            buf.clear();
            write_udp_packet(&mut buf, black_box(&addr), black_box(payload))
        })
    });
}

fn bench_udp_associate_request(c: &mut Criterion) {
    let addr = AddressRef {
        host: HostRef::Ipv4([0, 0, 0, 0]),
        port: 0,
    };
    let mut buf = BytesMut::new();
    write_request_header(&mut buf, &sample_hash(), CMD_UDP_ASSOCIATE, &addr).unwrap();
    let buf = buf.freeze();

    c.bench_function("parse_udp_associate_request", |b| {
        b.iter(|| parse_request(black_box(&buf)))
    });
}

criterion_group!(
    benches,
    bench_parse_request_ipv4,
    bench_parse_request_ipv6,
    bench_parse_request_domain,
    bench_parse_udp_packet_ipv4,
    bench_parse_udp_packet_domain,
    bench_write_request_header_ipv4,
    bench_write_request_header_domain,
    bench_write_udp_packet_ipv4,
    bench_write_udp_packet_domain,
    bench_udp_associate_request,
);

criterion_main!(benches);
