use crate::Parser;
use std::fs::File;
use std::io::Write;

const header: &str = r#"# include "vmlinux.h"
# include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md * ctx)
{
void * data = (void * )(long)ctx -> data;
void * data_end = (void * )(long)ctx -> data_end;
int pkt_sz = data_end - data;

bpf_printk("packet size: % d", pkt_sz);
return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

"#;

pub struct Generator {
    parser: Parser,
    output: File,
}

impl Generator {
    pub fn new(parser: Parser) -> Self {
        let mut output = File::create("prog.pbf.c").unwrap();
        Generator {
            parser,
            output: output,
        }
    }

    pub fn generate_program(&mut self) {
        self.output.write_all(header.as_bytes());
    }
}
