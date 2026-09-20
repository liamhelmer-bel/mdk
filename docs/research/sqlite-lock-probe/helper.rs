use std::{
    ffi::{CStr, c_char},
    path::Path,
};

/// Invoke the real helper from a disposable research process.
///
/// # Safety
/// `path` must point to a valid, NUL-terminated UTF-8 path for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn probe_private_db(path: *const c_char) -> i32 {
    let path = unsafe { CStr::from_ptr(path) }.to_str().unwrap();
    match fs_private::ensure_private_db_files(Path::new(path)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
