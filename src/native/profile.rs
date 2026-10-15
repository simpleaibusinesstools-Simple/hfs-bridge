//! Opt-in, aggregate diagnostics. No paths, file contents or per-request logs.
use std::{
    collections::BTreeMap,
    panic::Location,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Row {
    calls: u64,
    wait: Duration,
    work: Duration,
    maximum: Duration,
}
pub(super) struct Profile {
    rows: Option<Mutex<BTreeMap<u32, Row>>>,
}
impl Profile {
    pub(super) fn new() -> Self {
        Self {
            rows: std::env::var_os("HFS_NATIVE_PROFILE")
                .is_some()
                .then(|| Mutex::new(BTreeMap::new())),
        }
    }
    #[track_caller]
    pub(super) fn begin(&self) -> Option<Sample<'_>> {
        let line = Location::caller().line();
        self.rows.as_ref().map(|rows| Sample {
            rows,
            line,
            start: Instant::now(),
            wait: None,
        })
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        if let Some(rows) = &self.rows
            && let Ok(rows) = rows.lock()
        {
            for (line, row) in rows.iter() {
                eprintln!(
                    "NATIVE_PROFILE line={line} calls={} wait_ns={} work_ns={} max_ns={}",
                    row.calls,
                    row.wait.as_nanos(),
                    row.work.as_nanos(),
                    row.maximum.as_nanos()
                );
            }
        }
    }
}
pub(super) struct Sample<'a> {
    rows: &'a Mutex<BTreeMap<u32, Row>>,
    line: u32,
    start: Instant,
    wait: Option<Duration>,
}
impl Sample<'_> {
    pub(super) fn locked(&mut self) {
        self.wait = Some(self.start.elapsed());
    }
}
impl Drop for Sample<'_> {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        let wait = self.wait.unwrap_or(elapsed);
        let work = elapsed.saturating_sub(wait);
        if let Ok(mut rows) = self.rows.lock() {
            let row = rows.entry(self.line).or_default();
            row.calls += 1;
            row.wait += wait;
            row.work += work;
            row.maximum = row.maximum.max(work);
        }
    }
}
