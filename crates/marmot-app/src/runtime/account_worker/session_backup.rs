//! Best-effort encrypted backup scheduling under the account worker's root
//! lease. MLS writes wake a pass; the interval also covers ordinary traffic.
use crate::{AppClient, AppError};
use cgka_traits::storage::StorageProvider;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use storage_sqlite::IntegrityProbe;
use tokio::task::JoinHandle;

const PERIOD: Duration = Duration::from_secs(12 * 60 * 60);
const RETRY: Duration = Duration::from_secs(5 * 60);

pub(super) struct Schedule {
    enabled: bool,
    last_generation: Option<u64>,
    next_periodic: Instant,
    not_before: Instant,
    active: Option<(u64, JoinHandle<Result<IntegrityProbe, AppError>>)>,
    cancelled: Arc<AtomicBool>,
}

impl Schedule {
    pub(super) fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            last_generation: None,
            next_periodic: now,
            not_before: now,
            active: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) async fn poll(&mut self, client: &AppClient) {
        if !self.enabled {
            return;
        }
        if self
            .active
            .as_ref()
            .is_some_and(|(_, task)| task.is_finished())
        {
            let (generation, task) = self.active.take().expect("finished backup task exists");
            let status = match task.await {
                Ok(Ok(status)) => status,
                _ => IntegrityProbe::Incomplete,
            };
            let category = match status {
                IntegrityProbe::Healthy => "healthy",
                IntegrityProbe::Corrupt => "corrupt",
                IntegrityProbe::Incomplete => "incomplete",
            };
            tracing::info!(
                target: "marmot_app::session_backup",
                method = "backup_account_session",
                status = category,
                "encrypted session backup pass finished"
            );
            let now = Instant::now();
            if status == IntegrityProbe::Healthy {
                self.last_generation = client
                    .app
                    .session_backup_generation
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&client.state.label)
                    .map(|(generation, _)| *generation);
                self.next_periodic = now + PERIOD;
                self.not_before = now;
            } else {
                let changed = client
                    .app
                    .account_storage(&client.state.label)
                    .ok()
                    .and_then(|storage| storage.mls_write_generation())
                    != Some(generation);
                self.not_before = if changed { now } else { now + RETRY };
            }
        }
        if self.active.is_some() {
            return;
        }
        let Ok(storage) = client.app.account_storage(&client.state.label) else {
            return;
        };
        let Some(generation) = storage.mls_write_generation() else {
            return;
        };
        if !self.should_start(generation, Instant::now()) {
            return;
        }
        let app = client.app.clone();
        let label = client.state.label.clone();
        let cancelled = self.cancelled.clone();
        self.active = Some((
            generation,
            tokio::task::spawn_blocking(move || app.backup_account_session(&label, &cancelled)),
        ));
    }

    fn should_start(&self, generation: u64, now: Instant) -> bool {
        now >= self.not_before
            && (self.last_generation != Some(generation) || now >= self.next_periodic)
    }
}

impl Drop for Schedule {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mls_change_triggers_even_before_periodic_deadline() {
        let mut schedule = Schedule::new(true);
        let now = Instant::now();
        schedule.last_generation = Some(4);
        schedule.next_periodic = now + PERIOD;
        assert!(!schedule.should_start(4, now));
        assert!(schedule.should_start(5, now));
        schedule.not_before = now + RETRY;
        assert!(!schedule.should_start(5, now));
        assert!(schedule.should_start(5, now + RETRY));
    }
}
