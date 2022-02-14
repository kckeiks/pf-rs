use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::{tempdir, TempDir};

use crate::error::{Error, Result};

pub fn compile(src: &Path, dst: &Path) -> Result<()> {
    let clang = PathBuf::from("clang");
    let mut cmd = Command::new(clang.as_os_str());

    let libbpf_dir = tmp_setup_libbpf_headers()?;
    let options = format!("-I{}", libbpf_dir.as_ref().to_str().unwrap());
    cmd.args(options.split_whitespace());

    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        _ => std::env::consts::ARCH,
    };

    cmd.arg("-g")
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(format!("-D__TARGET_ARCH_{}", arch))
        .arg(src.as_os_str())
        .arg("-o")
        .arg(dst);

    let output = cmd.output().map_err(|e| Error::Build(e.to_string()))?;

    if !output.status.success() {
        return Err(Error::Build(format!(
            "clang failed to compile BPF program: {:?}",
            output
        )));
    }

    Ok(())
}

pub fn tmp_setup_libbpf_headers() -> Result<TempDir> {
    let tmpdir = tempdir().map_err(|e| Error::Build(e.to_string()))?;
    let hdrs_dir = tmpdir.path().join("bpf");
    fs::create_dir_all(&hdrs_dir).map_err(|e| Error::Build(e.to_string()))?;

    for (filename, data) in libbpf_sys::API_HEADERS.iter() {
        let path = hdrs_dir.as_path().join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)
            .map_err(|e| Error::Build(e.to_string()))?;
        file.write_all(data.as_bytes())
            .map_err(|e| Error::Build(e.to_string()))?;
    }
    Ok(tmpdir)
}
