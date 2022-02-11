const Headers: &str = r##"#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
"##;

const EthHdrParser: &str = r"
static int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;

    if (eth + 1 > data_end)
        return -1;

    nh->pos = eth + 1;
    *ethhdr = eth;
    return eth->h_proto;
}";

const Ipv4HdrParser: &str = r"
static int parse_ip4hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;

    /* check min hdr size */
    if (hdrsize < sizeof(iphdr))
        return -1;

    /* variable-length header */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;
    return iph->protocol;
}";

const FilterProg: &str = r#"
SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct hdr_cursor nh;
    int header_type;

    nh.pos = data;
    header_type = parse_ethhdr(&nh, data_end, &ethhdr);
    bpf_printk("hdr type: %d", header_type);
    header_type = parse_ip4hdr(&nh, data_end, &iphdr);
    bpf_printk("ip source: %pi4", &iphdr->saddr);
    return XDP_PASS;
}"#;

const CursorStruct: &str = "
struct hdr_cursor {
    void *pos;
};";

const License: &str = r#"char __license[] SEC("license") = "GPL";"#;
