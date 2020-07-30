extern crate nc;

use std::os::raw::c_char;
use std::ffi::CString;

pub const RUN_OCI_SECCOMP_NOTIFY_HANDLE_NOT_HANDLED: i32 = 0;
pub const RUN_OCI_SECCOMP_NOTIFY_HANDLE_SEND_RESPONSE: i32 = 1;
pub const RUN_OCI_SECCOMP_NOTIFY_HANDLE_DELAYED_RESPONSE: i32 = 2;

pub const P_PID: i32 = 1;

struct Device {
    from: &'static str,
    major: u32,
    minor: u32,
}

const ALLOWED_DEVICES: [Device; 5] = [
    Device{from: "/dev/null", major: 1, minor: 3},
    Device{from: "/dev/zero", major: 1, minor: 5},
    Device{from: "/dev/full", major: 1, minor: 7},
    Device{from: "/dev/random", major: 1, minor: 8},
    Device{from: "/dev/urandom", major: 1, minor: 9},
];


#[no_mangle]
pub struct LibcrunLoadSeccompNotifyConf {
    _runtime_root_path: *const c_char,
    _name: *const c_char,
    _bundle_path: *const c_char,
    _oci_config_path: *const c_char,
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_plugin_version() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_stop(_opaque: *mut core::ffi::c_void) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_start(_opaque: *mut *mut core::ffi::c_void, _conf: *mut LibcrunLoadSeccompNotifyConf, size_configuration: usize) -> i32
{
    if std::mem::size_of::<LibcrunLoadSeccompNotifyConf>() != size_configuration {
        return -nc::EINVAL;
    }
    0
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_handle_request(_opaque: *mut *mut core::ffi::c_void,
                                                        _sizes: *mut nc::seccomp_notif_sizes_t,
                                                        sreq: *mut nc::seccomp_notif_t,
                                                        sresp: *mut nc::seccomp_notif_resp_t,
                                                        _seccomp_fd: i32,
                                                        shandled: *mut i32) -> i32
{
    let req = unsafe {&mut *sreq};
    let resp = unsafe {&mut *sresp};
    let handled = unsafe {&mut *shandled};

    if req.data.nr == nc::SYS_MKNOD as i32 {
        match handle_mknod_request(req) {
            Ok(_) => {
                resp.error = 0;
            }
            Err(errno) => {
                resp.error = -errno;
            }
        }

        *handled = RUN_OCI_SECCOMP_NOTIFY_HANDLE_SEND_RESPONSE;
        resp.id = req.id;
        resp.val = 0;
        return 0;
    }

    *handled = RUN_OCI_SECCOMP_NOTIFY_HANDLE_NOT_HANDLED;
 0
}

fn get_string_from_buffer(fname_buffer: Vec<u8>) -> Result<String, nc::Errno> {
    let len = match fname_buffer.iter().position(|&x| x == 0) {
        Some(s) => {
            s
        }
        None => {
            return Err(nc::EINVAL);
        }

    };
    let f = match CString::new(&fname_buffer[0..len]) {
        Ok(s) => {
            s
        }
        Err(_) => {
            return Err(nc::EINVAL);
        }
    };
    let filename = match f.into_string() {
        Ok(s) => {
            s
        }
        Err(_) => {
            return Err(nc::EINVAL);
        }
    };
    Ok(filename)
}

fn handle_mknod_request(req: &mut nc::seccomp_notif_t) -> Result<u32, nc::Errno> {
    let fd = nc::open(&format!("/proc/{}/mem", req.pid), nc::O_RDONLY, 0)?;

    let mut fname_buffer = vec![0; nc::types::PATH_MAX as usize];
    match nc::pread64(fd, &mut fname_buffer, req.data.args[0] as isize) {
        Ok(_) => {
            nc::close(fd)?;
        }
        Err(errno) => {
            let _ = nc::close(fd);
            return Err(errno);
        }
    }

    let filename = get_string_from_buffer(fname_buffer);

    // Only char devices are allowed
    if (req.data.args[1] as u32 & nc::S_IFMT) != nc::S_IFCHR {
        return Err(nc::EPERM);
    }

    let major = ((req.data.args[2] >> 8) & 0xFF) as u32;
    let minor = (req.data.args[2] & 0xFF) as u32;

    let present: &Device = match ALLOWED_DEVICES.iter().find(|&x| x.major == major && x.minor == minor) {
        None => {
            return Err(nc::EPERM);
        }
        Some(x) => x
    };

    let mut hdr = nc::cap_user_header_t{
        version: nc::LINUX_CAPABILITY_VERSION_3 as u32,
        pid: req.pid as i32,
    };
    let mut udata = nc::cap_user_data_t{
        permitted: 0,
        effective: 0,
        inheritable: 0};
    nc::capget(&mut hdr, &mut udata)?;

    // The process has no CAP_MKNOD
    let has_cap_mknod = udata.effective & (1 << nc::types::CAP_MKNOD) != 0;
    if !has_cap_mknod {
        return Err(nc::EPERM);
    }

    let pid = nc::fork()?;
    if pid == 0 {
        nc::exit(0);
    }

    let mut info: nc::siginfo_t = {0, 0, 0};
    let mut usage: nc::rusage_t = {};
    nc::waitid(P_PID, pid, &mut info, 0, &mut usage)?;

    Ok(0)
}
