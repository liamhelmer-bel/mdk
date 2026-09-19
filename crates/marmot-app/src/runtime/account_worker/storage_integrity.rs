//! Periodic detection after readiness, using only fixed diagnostic categories.
use crate::AppClient;
use std::time::{Duration, Instant};
use storage_sqlite::IntegrityProbe;

const INTERVAL: Duration = Duration::from_secs(120);
const BUDGET: Duration = Duration::from_millis(250);

pub(super) struct Schedule {
    next: Instant,
}

impl Schedule {
    pub(super) fn new() -> Self {
        Self {
            next: Instant::now(),
        }
    }

    pub(super) fn tick(&mut self, client: &AppClient) {
        if Instant::now() < self.next {
            return;
        }
        let outcome = client.runtime.session().probe_storage_integrity(BUDGET);
        self.next = Instant::now() + INTERVAL;
        match outcome {
            Ok(IntegrityProbe::Healthy) => tracing::info!(
                target: "marmot_app::storage_integrity",
                method = "periodic_probe", status = "healthy",
                "account storage structural integrity check completed"
            ),
            Ok(IntegrityProbe::Corrupt) => tracing::error!(
                target: "marmot_app::storage_integrity",
                method = "periodic_probe", status = "corrupt",
                "account storage integrity check failed; operator recovery required"
            ),
            _ => tracing::warn!(
                target: "marmot_app::storage_integrity",
                method = "periodic_probe", status = "incomplete",
                "account storage integrity check incomplete; health is unknown"
            ),
        }
    }
}
