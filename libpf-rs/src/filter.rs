use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use tempfile::tempdir;

use crate::bpf::{BPFLink, BPFObj};
use crate::bpfcode::{
    DEFINES, EVAL_BOTH_IPVER, EVAL_NOOP, EVAL_ONLY_IP4, EVAL_ONLY_IP6, INCLUDE_HEADERS,
    IP4RULES_MAPS, IP4_EVAL_FUNCS, IP6RULES_MAPS, IP6_EVAL_FUNCS, PARSERS, PROGRAM, STRUCTS,
    VMLINUX,
};
use crate::error::Error;
use crate::rule::{Action, InnerRule, RawRule, Rule};
use crate::{bpf, compile};

#[derive(Debug)]
pub struct Filter {
    default_act: Action,
    ipv4_rules: Vec<RawRule>,
    ipv6_rules: Vec<RawRule>,
}

impl Filter {
    pub fn new() -> Self {
        Filter {
            default_act: Action::Pass,
            ipv4_rules: Vec::new(),
            ipv6_rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        match rule.get_rule() {
            InnerRule::IPv6Rule(r) => self.ipv6_rules.push(r),
            InnerRule::IPv4Rule(r) => self.ipv4_rules.push(r),
            InnerRule::DefaultRule(a) => self.default_act = a,
        }
    }

    pub fn load_on(self, ifindex: i32) -> Result<BPFLink> {
        let mut bpf_obj = self
            .generate_and_load()
            .map_err(|e| Error::Internal(e.to_string()))?;

        for (i, rule) in self.ipv4_rules.into_iter().enumerate() {
            let initial_value =
                bincode2::serialize(&rule).map_err(|e| Error::Internal(e.to_string()))?;
            let index =
                bincode2::serialize(&(i as u32)).map_err(|e| Error::Internal(e.to_string()))?;
            bpf_obj
                .update_map("ipv4_rules", &index, &initial_value, 0)
                .map_err(|e| Error::Internal(e.to_string()))?;
        }

        for (i, rule) in self.ipv6_rules.into_iter().enumerate() {
            let initial_value =
                bincode2::serialize(&rule).map_err(|e| Error::Internal(e.to_string()))?;
            let index =
                bincode2::serialize(&(i as u32)).map_err(|e| Error::Internal(e.to_string()))?;

            bpf_obj
                .update_map("ipv6_rules", &index, &initial_value, 0)
                .map_err(|e| Error::Internal(e.to_string()))?;
        }

        // attach prog
        let link = bpf_obj
            .attach_prog(ifindex)
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(link)
    }

    pub fn generate_src(self) -> Result<()> {
        let filename = "pfdebug";
        let src_dir = Path::new("./target/");

        let hdr_path = src_dir.join("vmlinux.h");
        let _hdr = generate_vmlinux_file(hdr_path.as_path())?;
        let src_path = src_dir.join(format!("{}.bpf.c", filename));
        self.generate_src_file(src_path.as_path())?;

        let obj_path = src_dir.join(format!("{}.o", filename));

        compile::compile(src_path.as_path(), obj_path.as_path())?;

        Ok(())
    }

    fn generate_and_load(&self) -> Result<BPFObj> {
        let filename = "pf";
        let src_dir = tempdir().expect("error creating temp dir");

        let hdr_path = src_dir.path().join("vmlinux.h");
        let hdr = generate_vmlinux_file(hdr_path.as_path())?;
        let src_path = src_dir.path().join(format!("{}.bpf.c", filename));
        let src = self.generate_src_file(src_path.as_path())?;

        let obj_dir = tempdir().expect("error creating temp dir");
        let obj_path = obj_dir.path().join(format!("{}.o", filename));

        compile::compile(src_path.as_path(), obj_path.as_path())?;

        let bpf_obj =
            bpf::BPFObj::load_from_file(obj_path).map_err(|e| Error::Internal(e.to_string()))?;

        drop(hdr);
        drop(src);

        if let Err(e) = src_dir.close() {
            println!("error closing dir: {}", e.to_string());
        }
        if let Err(e) = obj_dir.close() {
            println!("error closing dir: {}", e.to_string());
        }

        Ok(bpf_obj)
    }

    fn generate_src_file(&self, path: &Path) -> Result<File> {
        let mut src = File::create(path).map_err(|e| Error::Internal(e.to_string()))?;
        src.write_all(INCLUDE_HEADERS.as_bytes())
            .map_err(|e| Error::Internal(e.to_string()))?;
        src.write_all(DEFINES.as_bytes())
            .map_err(|e| Error::Internal(e.to_string()))?;
        src.write_all(
            format!(
                "\
            #define DEFAULT_ACTION {}\n\
            #define IPV4_RULE_COUNT {}\n\
            #define IPV6_RULE_COUNT {}\n",
                self.default_act as u32,
                self.ipv4_rules.len(),
                self.ipv6_rules.len()
            )
            .as_bytes(),
        )
        .map_err(|e| Error::Internal(e.to_string()))?;
        src.write_all(STRUCTS.as_bytes())
            .map_err(|e| Error::Internal(e.to_string()))?;
        src.write_all(PARSERS.as_bytes())
            .map_err(|e| Error::Internal(e.to_string()))?;

        if !self.ipv4_rules.is_empty() {
            src.write_all(IP4RULES_MAPS.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?;
            src.write_all(IP4_EVAL_FUNCS.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?;
        }

        if !self.ipv6_rules.is_empty() {
            src.write_all(IP6RULES_MAPS.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?;
            src.write_all(IP6_EVAL_FUNCS.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?;
        }

        match (self.ipv6_rules.is_empty(), self.ipv4_rules.is_empty()) {
            (true, true) => src
                .write_all(EVAL_NOOP.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?,
            (true, false) => src
                .write_all(EVAL_ONLY_IP4.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?,
            (false, true) => src
                .write_all(EVAL_ONLY_IP6.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?,
            (false, false) => src
                .write_all(EVAL_BOTH_IPVER.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?,
        }

        src.write_all(PROGRAM.as_bytes())
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(src)
    }
}

fn generate_vmlinux_file(path: &Path) -> Result<File> {
    let mut hdr = File::create(path).map_err(|e| Error::Internal(e.to_string()))?;
    if let Err(e) = hdr.write_all(VMLINUX.as_bytes()) {
        panic!("{}", e.to_string());
    }
    Ok(hdr)
}
