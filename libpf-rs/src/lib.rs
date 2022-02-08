use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, time};
use std::fmt::Alignment::Right;
use std::path::Path;
use ctrlc;
use tempfile::tempdir;
use bincode2;
use http::request;

mod bpf;
mod compile;
mod error;
mod filter;
mod ip;

const MAX_RULE_PER_FILTER: usize = 20;

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}

pub fn load_filter() {
    // // internally we will name the file so it should be in the right format
    // let file_name = "xdppass";
    // let src_file =  format!("./bpf/{}.bpf.c", file_name);
    // let src_path = Path::new(src_file.as_str());
    //
    // let tmpdir = tempdir().expect("error creating temp dir");
    // let dst_path = tmpdir.path().join(format!("{}.o", file_name));
    // compile::compile(src_path, dst_path.as_path()).expect("it failed!");
    //
    // let mut loader = bpf::Loader::load_from_file(dst_path).expect("loade from file failed");
    //
    // // add rules to filter
    // let rul = &filter::Raw
    // let initial_value= bincode2::serialize(rul).expect("serialized failed");
    // loader
    //     .update_map("rules", &[0, 0, 0, 0], &initial_value, 0)
    //     .expect("failed to update map");
    // loader
    //     .update_map("rules", &[1, 0, 0, 0], &initial_value, 0)
    //     .expect("failed to update map");
    //
    // // attach prog
    // let Link = loader.attach_prog(4).expect("failed to attach program");
    //
    // // /* keep it alive */
    // let running = Arc::new(AtomicBool::new(true));
    // let r = running.clone();
    // ctrlc::set_handler(move || {
    //     r.store(false, Ordering::SeqCst);
    // }).unwrap();
    //
    // while running.load(Ordering::SeqCst) {
    //     eprint!(".");
    //     thread::sleep(time::Duration::from_secs(1));
    // }

}