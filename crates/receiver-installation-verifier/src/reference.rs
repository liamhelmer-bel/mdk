//! Closed protected installation reference. Read-only evidence, never admission.
use crate::installation::{Error, Index, canonical, digest};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub root: PathBuf,
    pub index_sha256: String,
    pub recipe_id: String,
    pub platform_id: String,
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value != "."
        && value != ".."
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}
impl Installation {
    pub fn check(&self) -> Result<()> {
        if self.root.parent() != Some(Path::new("/opt/heterodyne-receiver/releases"))
            || !self.root.is_absolute()
            || !super::installation::hash_string(&self.index_sha256)
            || self.root.file_name().and_then(|s| s.to_str()) != Some(self.index_sha256.as_str())
            || !id(&self.recipe_id)
            || !id(&self.platform_id)
        {
            return Err(Error::Path);
        }
        Ok(())
    }
    pub fn source_sha256(&self) -> Result<String> {
        self.check()?;
        Ok(digest(&canonical(
            &serde_json::json!({"schema":"receiver-source-profile.v2",
            "index_sha256":self.index_sha256,"recipe_id":self.recipe_id,"platform_id":self.platform_id}),
        )?))
    }
    pub fn verify(&self) -> Result<Verified> {
        self.check()?;
        let root = open_protected(&self.root)?;
        let index = Index::read_published_until(
            &root,
            &self.index_sha256,
            Instant::now() + Duration::from_secs(120),
        )?;
        if index.recipe_id != self.recipe_id || index.platform_id != self.platform_id {
            return Err(Error::Encoding);
        }
        // The complete baseline bytes are corroborated independently of the tree.
        index.inspect_external_baseline(&open_protected(Path::new("/"))?)?;
        Ok(Verified {
            reference: self.clone(),
            root,
            index,
        })
    }
}
fn open_protected(path: &Path) -> Result<File> {
    let mut file = File::open("/").map_err(|_| Error::Path)?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => (),
            std::path::Component::Normal(name) => {
                protected_directory(&file)?;
                let name =
                    std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| Error::Path)?;
                let fd = unsafe {
                    libc::openat(
                        file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(Error::Path);
                }
                file = unsafe { File::from_raw_fd(fd) };
            }
            _ => return Err(Error::Path),
        }
    }
    protected_directory(&file)?;
    Ok(file)
}
fn protected_directory(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|_| Error::Path)?;
    if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7022 != 0 {
        return Err(Error::Path);
    }
    Ok(())
}
pub struct Verified {
    reference: Installation,
    root: File,
    index: Index,
}
impl Verified {
    pub fn check(&self) -> Result<()> {
        let current = open_protected(&self.reference.root)?;
        let old = self.root.metadata().map_err(|_| Error::Path)?;
        let new = current.metadata().map_err(|_| Error::Path)?;
        if (old.dev(), old.ino()) != (new.dev(), new.ino()) {
            return Err(Error::Path);
        }
        let checked = self.reference.verify()?;
        if canonical(&serde_json::to_value(&checked.index).map_err(|_| Error::Encoding)?)?
            != canonical(&serde_json::to_value(&self.index).map_err(|_| Error::Encoding)?)?
        {
            return Err(Error::Path);
        }
        Ok(())
    }
    pub fn python(&self) -> PathBuf {
        self.reference.root.join(&self.index.roles.python)
    }
    pub fn product_source(&self) -> PathBuf {
        self.reference.root.join(&self.index.roles.product_source)
    }
    pub fn purelib(&self) -> PathBuf {
        self.reference.root.join(&self.index.roles.purelib)
    }
    pub fn closure(&self) -> Result<Vec<(PathBuf, String)>> {
        self.index
            .entries
            .iter()
            .filter(|v| v[1] == "file")
            .map(|v| {
                Ok((
                    self.reference
                        .root
                        .join(v[0].as_str().ok_or(Error::Encoding)?),
                    v[4].as_str().ok_or(Error::Encoding)?.to_owned(),
                ))
            })
            .collect()
    }
}
