use anyhow::{anyhow, bail, Result};
use libbpf_sys;
use libbpf_sys::bpf_object;
use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::iter::Map;
use std::path::Path;
use std::ptr;

pub struct BPFLink {
    ptr: *mut libbpf_sys::bpf_link,
}

pub struct Loader {
    ptr: *mut libbpf_sys::bpf_object,
    progs: Vec<BPFProg>,
    maps: HashMap<String, BPFMap>,
}

impl Loader {
    pub fn load_from_file<T: AsRef<Path>>(src: T) -> Result<Self> {
        let obj_ptr = Loader::open_file(src.as_ref())?;

        let res = unsafe { libbpf_sys::bpf_object__load(obj_ptr) };
        if res != 0 {
            bail!("error {}: failed to load bpf object", -res);
        }

        let mut obj = Loader {
            ptr: obj_ptr,
            progs: Vec::new(),
            maps: HashMap::new(),
        };

        let mut prev_map: *mut libbpf_sys::bpf_map = std::ptr::null_mut();
        loop {
            let mut next_ptr = unsafe { libbpf_sys::bpf_object__next_map(obj.ptr, prev_map) };
            if next_ptr.is_null() {
                break;
            }

            // bpf_map__name does not return null unless we pass null
            let str_ptr = unsafe { libbpf_sys::bpf_map__name(next_ptr) };

            let c_str = unsafe { CStr::from_ptr(str_ptr) };
            let name = c_str.to_str()?.to_string();

            let fd = unsafe { libbpf_sys::bpf_map__fd(next_ptr) };
            if fd < 0 {
                bail!("error {}: failed to get file descriptor", -fd);
            }

            // bpf_map__def does not return null unless we pass null
            let map_def = unsafe { ptr::read(libbpf_sys::bpf_map__def(next_ptr)) };

            obj.maps.insert(
                name,
                BPFMap::new(next_ptr, fd, map_def.key_size, map_def.value_size),
            );
            prev_map = next_ptr;
        }

        // we're only expecting to handle one program but this will make it easier to extend
        let mut prev_prog: *mut libbpf_sys::bpf_program = std::ptr::null_mut();
        loop {
            let mut next_ptr = unsafe { libbpf_sys::bpf_object__next_program(obj.ptr, prev_prog) };
            if next_ptr.is_null() {
                break;
            }

            obj.progs.push(BPFProg::new(next_ptr));
            prev_prog = next_ptr;
        }

        Ok(obj)
    }

    fn open_file(path: &Path) -> Result<*mut libbpf_sys::bpf_object> {
        let filename = path.file_name().ok_or(anyhow!("invalid path"))?;
        let name = filename
            .to_str()
            .ok_or(anyhow!("filename contains invalid Unicode"))?;

        if !name.ends_with(".o") {
            bail!("filename does not have .o extension");
        }

        let str_path = path.to_str().ok_or(anyhow!("invalid unicode in path"))?;
        let c_name = CString::new(str_path)?;
        let obj_opts = libbpf_sys::bpf_object_open_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
            object_name: c_name.as_ptr(),
            ..Default::default()
        };

        let obj = unsafe { libbpf_sys::bpf_object__open_file(c_name.as_ptr(), &obj_opts) };
        let err = unsafe { libbpf_sys::libbpf_get_error(obj as *const _) };
        if err != 0 {
            bail!("error {}: could not attach prog to xdp hook", err as i32);
        }

        Ok(obj)
    }

    pub fn update_map<T: AsRef<str>>(&mut self, name: T, key: &[u8], value: &[u8], map: u64) -> Result<()> {
        match self.maps.get_mut(name.as_ref()) {
            Some(m) => {
                m.update_map(key, value, map)
            }
            _ => bail!("unknown map")
        }
    }

    pub fn attach_prog(&mut self, ifindex: i32) -> Result<BPFLink> {
        // for now we only support one program
        match self.progs.get_mut(0) {
            Some(p) => {
                p.attach_xdp(ifindex)
            },
            _ => bail!("failed to retrieve prog")
        }
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_object__close(self.ptr);
        }
    }
}

struct BPFMap {
    map_ptr: *mut libbpf_sys::bpf_map,
    fd: i32,
    key_size: u32,
    val_size: u32,
}

impl BPFMap {
    fn new(map_ptr: *mut libbpf_sys::bpf_map, fd: i32, key_size: u32, val_size: u32) -> Self {
        BPFMap {
            map_ptr,
            fd,
            key_size,
            val_size,
        }
    }

    fn update_map(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<()> {
        if key.len() != self.key_size as usize {
            bail!("invalid key size for map");
        };

        if value.len() != self.val_size as usize {
            bail!("invalid value size for map");
        };

        let res = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.fd as i32,
                key.as_ptr() as *const c_void,
                value.as_ptr() as *const c_void,
                flags as libbpf_sys::__u64,
            )
        };

        if res < 0 {
            bail!("failed to update the map");
        } else {
            Ok(())
        }
    }
}

struct BPFProg {
    ptr: *mut libbpf_sys::bpf_program,
}

impl BPFProg {
    fn new(ptr: *mut libbpf_sys::bpf_program) -> Self {
        BPFProg { ptr: ptr }
    }

    fn attach_xdp(&mut self, ifindex: i32) -> Result<BPFLink> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_xdp(self.ptr, ifindex) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            bail!("error {}: could not attach prog to xdp hook", err as i32);
        }

        Ok(BPFLink { ptr })
    }
}
