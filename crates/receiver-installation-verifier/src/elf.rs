//! Bounded non-executing ELF64/x86-64 dependency inspection, not dlopen policy.
use std::collections::BTreeSet;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Unsupported,
    Bound,
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, PartialEq, Eq)]
pub struct Dependencies {
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
}
fn slice(raw: &[u8], at: u64, len: u64) -> Result<&[u8]> {
    let end = at.checked_add(len).ok_or(Error::Bound)?;
    raw.get(
        usize::try_from(at).map_err(|_| Error::Bound)?
            ..usize::try_from(end).map_err(|_| Error::Bound)?,
    )
    .ok_or(Error::Encoding)
}
fn word(raw: &[u8], at: u64, len: u64) -> Result<u64> {
    let mut out = [0; 8];
    let data = slice(raw, at, len)?;
    out[..data.len()].copy_from_slice(data);
    Ok(u64::from_le_bytes(out))
}
fn text(raw: &[u8], at: u64) -> Result<String> {
    let rest = raw
        .get(usize::try_from(at).map_err(|_| Error::Bound)?..)
        .ok_or(Error::Encoding)?;
    let end = rest
        .iter()
        .take(4096)
        .position(|b| *b == 0)
        .ok_or(Error::Bound)?;
    let value = std::str::from_utf8(&rest[..end]).map_err(|_| Error::Encoding)?;
    if value.is_empty()
        || !value.is_ascii()
        || value.bytes().any(|b| b.is_ascii_control() || b == b'$')
    {
        return Err(Error::Unsupported);
    }
    Ok(value.into())
}
#[derive(Clone, Copy)]
struct Segment {
    kind: u64,
    offset: u64,
    address: u64,
    size: u64,
}
fn segments(raw: &[u8]) -> Result<Vec<Segment>> {
    if raw.len() < 64 || raw.len() > 256 * 1024 * 1024 {
        return Err(Error::Bound);
    }
    if &raw[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(raw[7], 0 | 3)
        || raw[8..16].iter().any(|b| *b != 0)
        || !matches!(word(raw, 16, 2)?, 2 | 3)
        || word(raw, 18, 2)? != 62
        || word(raw, 20, 4)? != 1
        || word(raw, 52, 2)? != 64
        || word(raw, 54, 2)? != 56
    {
        return Err(Error::Unsupported);
    }
    let count = word(raw, 56, 2)?;
    if count == 0 || count > 1024 {
        return Err(Error::Bound);
    }
    let table = word(raw, 32, 8)?;
    slice(raw, table, count * 56)?;
    let mut out = Vec::new();
    for i in 0..count {
        let at = table + i * 56;
        let s = Segment {
            kind: word(raw, at, 4)?,
            offset: word(raw, at + 8, 8)?,
            address: word(raw, at + 16, 8)?,
            size: word(raw, at + 32, 8)?,
        };
        slice(raw, s.offset, s.size)?;
        if s.size > word(raw, at + 40, 8)? {
            return Err(Error::Encoding);
        }
        out.push(s);
    }
    Ok(out)
}
fn single(segments: &[Segment], kind: u64) -> Result<Option<Segment>> {
    let mut found = segments.iter().filter(|s| s.kind == kind);
    let result = found.next().copied();
    if found.next().is_some() {
        return Err(Error::Encoding);
    }
    Ok(result)
}
fn address(segments: &[Segment], address: u64, size: u64) -> Result<u64> {
    let mut result = None;
    for s in segments.iter().filter(|s| s.kind == 1) {
        if let Some(delta) = address.checked_sub(s.address)
            && delta.checked_add(size).is_some_and(|n| n <= s.size)
        {
            let offset = s.offset.checked_add(delta).ok_or(Error::Bound)?;
            if result.replace(offset).is_some() {
                return Err(Error::Unsupported);
            }
        }
    }
    result.ok_or(Error::Encoding)
}
fn dynamic(raw: &[u8], s: Segment) -> Result<Vec<(u64, u64)>> {
    if s.size == 0 || !s.size.is_multiple_of(16) || s.size / 16 > 4096 {
        return Err(Error::Bound);
    }
    let mut out = Vec::new();
    let mut ended = false;
    for i in 0..s.size / 16 {
        let tag = word(raw, s.offset + i * 16, 8)?;
        let value = word(raw, s.offset + i * 16 + 8, 8)?;
        if ended {
            if tag != 0 || value != 0 {
                return Err(Error::Encoding);
            }
            continue;
        }
        if tag == 0 {
            if value != 0 {
                return Err(Error::Encoding);
            }
            ended = true;
            continue;
        }
        // Closed known data/relocation/version tags; no search override/audit/filter.
        match tag {
            1..=14
            | 16..=30
            | 32
            | 33
            | 35..=37
            | 0x6ffffef5
            | 0x6ffffff0
            | 0x6ffffff9..=0x6fffffff => {}
            _ => return Err(Error::Unsupported),
        }
        // DT_RUNPATH is included in the numeric data range but never admitted.
        if tag == 29 || (tag == 30 && value & 1 != 0) || (tag == 0x6ffffffb && value & 0x80 != 0) {
            return Err(Error::Unsupported);
        }
        out.push((tag, value));
    }
    if !ended {
        return Err(Error::Encoding);
    }
    Ok(out)
}
fn unique(tags: &[(u64, u64)], tag: u64) -> Result<Option<u64>> {
    let mut values = tags.iter().filter(|(key, _)| *key == tag).map(|(_, v)| *v);
    let out = values.next();
    if values.next().is_some() {
        return Err(Error::Encoding);
    }
    Ok(out)
}
pub fn inspect(raw: &[u8]) -> Result<Dependencies> {
    let segments = segments(raw)?;
    let interpreter = single(&segments, 3)?
        .map(|s| {
            let data = slice(raw, s.offset, s.size)?;
            let value = text(data, 0)?;
            if value.len() + 1 != data.len()
                || !value.starts_with('/')
                || value
                    .split('/')
                    .skip(1)
                    .any(|v| v.is_empty() || v == "." || v == "..")
            {
                return Err(Error::Unsupported);
            }
            Ok(value)
        })
        .transpose()?;
    let Some(segment) = single(&segments, 2)? else {
        return Ok(Dependencies {
            interpreter,
            needed: Vec::new(),
            soname: None,
        });
    };
    let tags = dynamic(raw, segment)?;
    let size = unique(&tags, 10)?.ok_or(Error::Encoding)?;
    if size == 0 || size > 16 * 1024 * 1024 {
        return Err(Error::Bound);
    }
    let strings = slice(
        raw,
        address(&segments, unique(&tags, 5)?.ok_or(Error::Encoding)?, size)?,
        size,
    )?;
    let library = |at| -> Result<String> {
        let name = text(strings, at)?;
        if name.len() > 255 || name.contains('/') || name == "." || name == ".." {
            return Err(Error::Unsupported);
        }
        Ok(name)
    };
    let mut seen = BTreeSet::new();
    let mut needed = Vec::new();
    for (_, v) in tags.iter().filter(|(tag, _)| *tag == 1) {
        let name = library(*v)?;
        if needed.len() >= 256 || !seen.insert(name.clone()) {
            return Err(Error::Bound);
        }
        needed.push(name)
    }
    let soname = unique(&tags, 14)?.map(library).transpose()?;
    Ok(Dependencies {
        interpreter,
        needed,
        soname,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn put(raw: &mut [u8], at: usize, value: u64, size: usize) {
        raw[at..at + size].copy_from_slice(&value.to_le_bytes()[..size])
    }
    fn fixture() -> Vec<u8> {
        let mut raw = vec![0; 1024];
        raw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, v, n) in [
            (16, 3, 2),
            (18, 62, 2),
            (20, 1, 4),
            (32, 64, 8),
            (52, 64, 2),
            (54, 56, 2),
            (56, 3, 2),
        ] {
            put(&mut raw, at, v, n)
        }
        for (at, kind, offset, address, size) in [
            (64, 1, 0, 0x400000, 1024),
            (120, 2, 256, 0x400100, 80),
            (176, 3, 400, 0, 28),
        ] {
            for (d, v, n) in [
                (0, kind, 4),
                (8, offset, 8),
                (16, address, 8),
                (32, size, 8),
                (40, size, 8),
            ] {
                put(&mut raw, at + d, v, n)
            }
        }
        for (i, (tag, v)) in [(5, 0x400200), (10, 32), (1, 1), (14, 11), (0, 0)]
            .into_iter()
            .enumerate()
        {
            put(&mut raw, 256 + i * 16, tag, 8);
            put(&mut raw, 264 + i * 16, v, 8)
        }
        raw[400..428].copy_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
        let strings = b"\0libc.so.6\0self.so.1\0";
        raw[512..512 + strings.len()].copy_from_slice(strings);
        raw
    }
    #[test]
    fn nonexecuting_extract_and_search_override_refusal() {
        let original = fixture();
        let got = inspect(&original).unwrap();
        assert_eq!(
            got.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(got.needed, ["libc.so.6"]);
        assert_eq!(got.soname.as_deref(), Some("self.so.1"));
        let mut raw = original.clone();
        put(&mut raw, 256 + 3 * 16, 29, 8);
        assert_eq!(inspect(&raw), Err(Error::Unsupported));
        let mut raw = original.clone();
        put(&mut raw, 264, u64::MAX, 8);
        assert!(inspect(&raw).is_err());
        let mut raw = original.clone();
        put(&mut raw, 64 + 32, u64::MAX, 8);
        assert!(inspect(&raw).is_err());
        for length in 0..original.len() {
            assert!(inspect(&original[..length]).is_err())
        }
    }
    #[test]
    #[ignore = "host-specific Linux x86-64 ELF control, not platform qualification"]
    fn actual_host_elf_parser_control_not_platform_qualification() {
        let raw = std::fs::read("/usr/bin/true").unwrap();
        let got = inspect(&raw).unwrap();
        assert!(got.needed.iter().any(|s| s == "libc.so.6"));
    }
}
