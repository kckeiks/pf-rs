use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, time};
use std::net::Ipv4Addr;
use std::fs::File;
use std::io::Write;

use std::path::Path;
use tempfile::{tempdir, TempDir};
use crate::{bpf, compile};
use crate::bpf::Loader;
use crate::rule::{Rule, Action, InnerRule, RawRule};
use crate::bpfcode::{BPF_SRC, VMLINUX};

#[derive(Debug)]
pub struct Filter {
    default_act: Action,
    ipv4_rules: Vec<RawRule>,
    ipv6_rules: Vec<RawRule>,

}

impl Filter {
    pub fn new() -> Self {
        Filter { default_act: Action::Pass, ipv4_rules: Vec::new(), ipv6_rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        match rule.read_rule() {
            InnerRule::IPv6Rule(r) => self.ipv6_rules.push(r),
            InnerRule::IPv4Rule(r) => self.ipv4_rules.push(r),
            InnerRule::DefaultRule(r) => self.default_act = r
        }
    }

    pub fn load_on(self, ifindex: i32) -> Result<(), ()> {
        let mut loader = generate_and_load().unwrap();

        // add rules to filter
        // before we get here, program map must know how many rules
        for (i, rule) in self.ipv4_rules.into_iter().enumerate() {
            let initial_value= bincode2::serialize(&rule)
                .expect("rule serializer failed");
            let index = bincode2::serialize(&(i as u32))
                .expect("could not deserialize index");

            loader
                .update_map("ipv4_rules", &index, &initial_value, 0).unwrap();
        }

        for (i, rule) in self.ipv6_rules.into_iter().enumerate() {
            let initial_value= bincode2::serialize(&rule)
                .expect("rule serializer failed");
            let index = bincode2::serialize(&(i as u32))
                .expect("could not deserialize index");

            loader
                .update_map("ipv6_rules", &index, &initial_value, 0).unwrap();
        }

        // attach prog
        let Link = loader.attach_prog(ifindex).expect("failed to attach program");

        // /* keep it alive */
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).unwrap();

        while running.load(Ordering::SeqCst) {
            eprint!(".");
            thread::sleep(time::Duration::from_secs(1));
        }

        Ok(())
    }
}

fn generate_and_load() -> Result<Loader, ()> {
    let filename = "pf";
    let src_dir = tempdir().expect("error creating temp dir");

    let src_path = src_dir.path().join(format!("{}.bpf.c", filename));
    let mut src = File::create(src_path.as_path()).unwrap();
    if let Err(e) = src.write_all(BPF_SRC.as_bytes()) {
        panic!("could not write src code")
    }

    let hdr_path = src_dir.path().join("vmlinux.h");
    let mut hdr = File::create(hdr_path.as_path()).unwrap();
    if let Err(e) = hdr.write_all(VMLINUX.as_bytes()) {
        panic!("could not write vmlinux header")
    }

    let obj_dir = tempdir().expect("error creating temp dir");
    let obj_path = obj_dir.path().join(format!("{}.o", filename));

    compile::compile(src_path.as_path(), obj_path.as_path()).expect("it failed!");

    let loader = bpf::Loader::load_from_file(obj_path).expect("loade from file failed");

    // TODO: just log these
    src_dir.close().expect("coult not close src dir");
    obj_dir.close().expect("coult not close obj dir");

    Ok(loader)
}
