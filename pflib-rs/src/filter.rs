use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, time};
use std::net::Ipv4Addr;
use std::fs::File;
use std::io::Write;

use std::path::Path;
use tempfile::{tempdir, TempDir};
use anyhow::Result;
use crate::{bpf, compile};
use crate::bpf::Loader;
use crate::rule::{Rule, Action, InnerRule, RawRule};
use crate::bpfcode::{BPF_SRC, DEFINES, INCLUDE_HEADERS, VMLINUX};
use crate::error::Error;

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
            InnerRule::DefaultRule(a) => self.default_act = a
        }
    }

    pub fn load_on(self, ifindex: i32) -> Result<()> {
        let mut loader = self.generate_and_load()
            .map_err(|e| Error::Internal(e.to_string()))?;

        for (i, rule) in self.ipv4_rules.into_iter().enumerate() {
            let initial_value= bincode2::serialize(&rule)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let index = bincode2::serialize(&(i as u32))
                .map_err(|e| Error::Internal(e.to_string()))?;

            loader.update_map("ipv4_rules", &index, &initial_value, 0)
                .map_err(|e| Error::Internal(e.to_string()));
        }

        for (i, rule) in self.ipv6_rules.into_iter().enumerate() {
            let initial_value= bincode2::serialize(&rule)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let index = bincode2::serialize(&(i as u32))
                .map_err(|e| Error::Internal(e.to_string()))?;

            loader.update_map("ipv6_rules", &index, &initial_value, 0)
                .map_err(|e| Error::Internal(e.to_string()))?;
        }

        // attach prog
        let Link = loader.attach_prog(ifindex)
            .map_err(|e| Error::Internal(e.to_string()))?;

        // /* keep it alive */
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).map_err(|e| Error::Internal(e.to_string()))?;

        while running.load(Ordering::SeqCst) {
            eprint!(".");
            thread::sleep(time::Duration::from_secs(1));
        }

        Ok(())
    }

    fn generate_and_load(&self) -> Result<Loader> {
        let filename = "pf";
        let src_dir = tempdir()?;

        let hdr_path = src_dir.path().join("vmlinux.h");
        let hdr = generate_vmlinux_file(hdr_path.as_path());
        let src_path = src_dir.path().join(format!("{}.bpf.c", filename));
        let src = self.generate_src_file(src_path.as_path())?;

        let obj_dir = tempdir().expect("error creating temp dir");
        let obj_path = obj_dir.path().join(format!("{}.o", filename));

        compile::compile(src_path.as_path(), obj_path.as_path())?;

        let loader = bpf::Loader::load_from_file(obj_path)?;

        drop(hdr);
        drop(src);

        if let Err(e) = src_dir.close() {
            println!("coult not close src dir");
        }
        if let Err(e) = obj_dir.close() {
            println!("coult not close obj dir");
        }

        Ok(loader)
    }

    fn generate_src_file(&self, path: &Path) -> Result<File> {
        let mut src = File::create(path)?;
        src.write_all(INCLUDE_HEADERS.as_bytes())?;
        src.write_all(DEFINES.as_bytes())?;
        src.write_all(
            format!("\
            #define DEFAULT_ACTION {}\n\
            #define IPV4_RULE_COUNT {}\n\
            #define IPV6_RULE_COUNT {}\n",
                    self.default_act as u32,
                    self.ipv4_rules.len(),
                    self.ipv6_rules.len()).as_bytes()
        )?;
        src.write_all(BPF_SRC.as_bytes())?;

        Ok(src)
    }
}

fn generate_vmlinux_file(path: &Path) -> Result<File> {
    let mut hdr = File::create(path)?;
    if let Err(e) = hdr.write_all(VMLINUX.as_bytes()) {
        panic!("could not write vmlinux header")
    }
    Ok(hdr)
}

