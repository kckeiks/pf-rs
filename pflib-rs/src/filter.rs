use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, time};
use std::net::Ipv4Addr;

use std::path::Path;
use tempfile::tempdir;
use crate::{bpf, compile};
use crate::rule::{Rule, Action, InnerRule, RawRule};

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
        // internally we will name the file so it should be in the right format
        // TODO: Generate bpf.c file
        let file_name = "xdppass";
        let src_file =  format!("./bpf/{}.bpf.c", file_name);
        let src_path = Path::new(src_file.as_str());

        let tmpdir = tempdir().expect("error creating temp dir");
        let dst_path = tmpdir.path().join(format!("{}.o", file_name));
        compile::compile(src_path, dst_path.as_path()).expect("it failed!");

        let mut loader = bpf::Loader::load_from_file(dst_path).expect("loade from file failed");

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
