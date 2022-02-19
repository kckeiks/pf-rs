Warning: This project is currently in development. 

# pf-rs

`pf-rs` allows you to easily create and maintain packet filters.
You can specify the criteria for your filter via filter rules, 
that use Layer 3 & 4 header information, and `pf-rs` will create 
an eBPF program and attach it to the XDP hook for fast packet filtering.

The syntax to specify the rules was inspired by OpenBSD's pf.

### Example

Given the rule below, `pf-rs` will create a filter to block any IPv4 
packet with source address 10.11.4.2 or 10.11.5.2 to the destination 
address 10.11.3.2.

```
blocklist = {  10.11.4.2 10.11.5.2 }

block from $blocklist to 10.11.3.2
```

# libpf-rs

A Rust library for implementing eBPF-based packet filters. 
It provides an API for creating filter rules via a `Builder` 
and building and attaching a packet filter via a `Filter`.

This library uses [libbpf](https://github.com/libbpf/libbpf) and the rust bindings for it [libbpf-sys](https://github.com/libbpf/libbpf-sys). 
Integration with [libbpf-rs](https://github.com/libbpf/libbpf-rs) is planned once the API stabilizes.


### Example

Given the code below, `libpf-rs` will create an eBPF program 
that filters (blocks) incoming packets based on the given addresses 
and loads it on the device with index 4.

```Rust
use libpf_rs::filter::Filter;
use libpf_rs::rule::Builder;

fn main() {
    let ifindex: i32 = 4;
    let addrs = [
        ("10.11.4.2", "10.11.3.2"),
        ("10.11.6.2", "10.11.3.2"),
        ("10.11.5.2", "10.11.2.2"),
        ("10.11.127.2", "100.11.2.2"),
        ("0:0:0:0:0:FFFF:204.152.189.116", "1:0:0:0:0:0:0:8"),
        ("0:0:0:0:0:FFFF:204.152.189.116", "1:0:0:0:0:0:0:8"),
    ];

    let mut filter = Filter::new();

    for (src, dst) in addrs.into_iter() {
        filter.add_rule(
            Builder::new()
                .block()
                .from_addr(src)
                .to_addr(dst)
                .build()
                .unwrap(),
        );
    }

    let _link = filter.load_on(ifindex);
    
    // load_on() returns bpf_link
    // eBPF program will be detached once link is dropped
    // please see libbpf's doc for more info
    loop {}
}
```

# Feature Checklist

Some of these are WIP.

### `pf-rs`
- [x] supports macros
- [X] supports lists
- [ ] supports default actions (`pass all` and `block all`)
- [ ] support nested lists
- [ ] support macro in lists

### `libpf-rs`
- [x] supports IPv4 and IPv6
- [x] supports default actions (`pass all` and `block all`)
- [x] supports `quick` option (stops rule processing and performs action on first match)
- [x] supports UDP
- [x] supports stateless TCP (only port information) 
- [ ] supports stateful inspections
- [ ] supports HTTP
- [ ] supports SSH
