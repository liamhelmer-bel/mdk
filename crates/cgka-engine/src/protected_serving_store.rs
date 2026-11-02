//! Protected conversation delivery history. Records are transport state, never
//! semantic approval receipts. Unknown or incomplete effects stay held.
use super::*;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};

const MAX_RECORD: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub(super) enum Record {
    Binding {
        generation: String,
        enrollment_sha256: String,
    },
    Intent {
        key: String,
        content: serde_json::Value,
        epoch: u64,
    },
    Prepared {
        key: String,
        message_id: String,
        wire: TransportMessage,
    },
    Published {
        key: String,
    },
    ConvergenceStarted,
    ConvergenceFinished {
        settled: bool,
    },
}
#[derive(Clone)]
pub(super) struct Outbound {
    pub content: serde_json::Value,
    pub epoch: u64,
    pub prepared: Option<(String, TransportMessage)>,
    pub published: bool,
}
pub(super) struct Store {
    file: File,
    pub outbound: BTreeMap<String, Outbound>,
    binding: Option<(String, String)>,
    convergence_pending: bool,
}
impl Store {
    pub fn open(file: File, generation: &str, enrollment: &str) -> Result<Self, ReceiverHold> {
        let m = file.metadata().map_err(|_| ReceiverHold::Journal)?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o600
            || flags < 0
            || flags & libc::O_ACCMODE != libc::O_RDWR
        {
            return Err(ReceiverHold::Configuration);
        }
        file.try_lock().map_err(|_| ReceiverHold::Journal)?;
        (&file)
            .seek(SeekFrom::Start(0))
            .map_err(|_| ReceiverHold::Journal)?;
        let mut reader = BufReader::new(file.try_clone().map_err(|_| ReceiverHold::Journal)?);
        let mut s = Self {
            file,
            outbound: BTreeMap::new(),
            binding: None,
            convergence_pending: false,
        };
        loop {
            let mut raw = Vec::new();
            let n = (&mut reader)
                .take(MAX_RECORD + 1)
                .read_until(b'\n', &mut raw)
                .map_err(|_| ReceiverHold::Journal)?;
            if n == 0 {
                break;
            }
            if n as u64 > MAX_RECORD || raw.last() != Some(&b'\n') {
                return Err(ReceiverHold::ChangedState);
            }
            s.apply(
                serde_json::from_slice::<Record>(&raw).map_err(|_| ReceiverHold::ChangedState)?,
            )?;
        }
        drop(reader);
        match &s.binding {
            Some((g, e)) if g == generation && e == enrollment => (),
            Some(_) => return Err(ReceiverHold::ChangedState),
            None => s.append(Record::Binding {
                generation: generation.into(),
                enrollment_sha256: enrollment.into(),
            })?,
        }
        if s.convergence_pending {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(s)
    }
    fn apply(&mut self, record: Record) -> Result<(), ReceiverHold> {
        self.validate(&record)?;
        match record {
            Record::ConvergenceStarted => self.convergence_pending = true,
            Record::ConvergenceFinished { .. } => self.convergence_pending = false,
            Record::Binding {
                generation,
                enrollment_sha256,
            } => {
                self.binding = Some((generation, enrollment_sha256));
            }
            Record::Intent {
                key,
                content,
                epoch,
            } => {
                self.outbound.insert(
                    key,
                    Outbound {
                        content,
                        epoch,
                        prepared: None,
                        published: false,
                    },
                );
            }
            Record::Prepared {
                key,
                message_id,
                wire,
            } => {
                self.outbound
                    .get_mut(&key)
                    .ok_or(ReceiverHold::ChangedState)?
                    .prepared = Some((message_id, wire));
            }
            Record::Published { key } => {
                self.outbound
                    .get_mut(&key)
                    .ok_or(ReceiverHold::ChangedState)?
                    .published = true;
            }
        }
        Ok(())
    }
    fn validate(&self, record: &Record) -> Result<(), ReceiverHold> {
        if self.convergence_pending && !matches!(record, Record::ConvergenceFinished { .. }) {
            return Err(ReceiverHold::ChangedState);
        }
        let valid = match record {
            Record::ConvergenceStarted => self.binding.is_some() && !self.convergence_pending,
            Record::ConvergenceFinished { .. } => self.convergence_pending,
            Record::Binding { .. } => self.binding.is_none() && self.outbound.is_empty(),
            Record::Intent { key, .. } => {
                self.binding.is_some() && !key.is_empty() && !self.outbound.contains_key(key)
            }
            Record::Prepared {
                key, message_id, ..
            } => {
                !message_id.is_empty()
                    && self.outbound.get(key).is_some_and(|p| p.prepared.is_none())
            }
            Record::Published { key } => self
                .outbound
                .get(key)
                .is_some_and(|p| p.prepared.is_some() && !p.published),
        };
        if valid {
            Ok(())
        } else {
            Err(ReceiverHold::ChangedState)
        }
    }
    pub fn append(&mut self, record: Record) -> Result<(), ReceiverHold> {
        self.validate(&record)?;
        let mut raw = serde_json::to_vec(&record).map_err(|_| ReceiverHold::Malformed)?;
        raw.push(b'\n');
        if raw.len() as u64 > MAX_RECORD {
            return Err(ReceiverHold::Capacity);
        }
        self.file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&raw))
            .and_then(|_| self.file.sync_all())
            .map_err(|_| ReceiverHold::Journal)?;
        self.apply(record)
    }
}
