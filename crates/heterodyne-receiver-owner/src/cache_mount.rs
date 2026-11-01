//! Ephemeral relay spool lives on its own private tmpfs, never durable storage.
use std::{
    fs::File,
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(crate) fn create(durable: &[&File]) -> io::Result<File> {
    if unsafe { libc::geteuid() } != 0 || durable.is_empty() {
        return Err(io::Error::other("cache mount custody"));
    }
    // material_mount already supplies the private /mnt parent. Refuse an
    // existing name rather than adopting any previous cache or mount.
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) != 0
            || libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            || libc::mkdir(c"/mnt/heterodyne-receiver-cache".as_ptr(), 0o700) != 0
            || libc::mount(
                c"tmpfs".as_ptr(),
                c"/mnt/heterodyne-receiver-cache".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"mode=0700,uid=899,gid=899,size=67108864".as_ptr().cast(),
            ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let cache = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/mnt/heterodyne-receiver-cache")?;
    let m = cache.metadata()?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(cache.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if !m.is_dir()
        || m.uid() != 899
        || m.gid() != 899
        || m.mode() & 0o7777 != 0o700
        || unsafe { fs.assume_init() }.f_type != libc::TMPFS_MAGIC
    {
        return Err(io::Error::other("cache filesystem custody"));
    }
    for file in durable {
        if file.metadata()?.dev() == m.dev() {
            return Err(io::Error::other("cache aliases durable filesystem"));
        }
    }
    Ok(cache)
}
