//! Catalog fork ownership, refreshed from current record bodies before a query.
//! Journal, bitmap, special-file and overflow checks remain with the caller.
use std::collections::{BTreeMap, BTreeSet};

pub(super) type RecordKey = (u32, Vec<u16>);
type Span = (u32, u64);

#[derive(Default)]
struct Bucket {
    ends: BTreeMap<Span, usize>,
    max_end: u64,
}

#[derive(Default)]
pub(super) struct CatalogOwnership {
    initialized: bool,
    pending: BTreeSet<RecordKey>,
    records: BTreeMap<RecordKey, Vec<Span>>,
    malformed_files: BTreeSet<RecordKey>,
    // At most 65536 buckets cover every possible u32 allocation-block start.
    // A long extent belongs to its start bucket; max_end retains its reach.
    buckets: BTreeMap<u16, Bucket>,
    #[cfg(test)]
    pub(super) decoded_records: usize,
}

impl CatalogOwnership {
    pub(super) fn initialized(&self) -> bool {
        self.initialized
    }

    pub(super) fn finish_initialization(&mut self) {
        self.initialized = true;
    }

    pub(super) fn changed(&mut self, key: RecordKey) {
        if self.initialized {
            self.pending.insert(key);
        }
    }

    pub(super) fn take_pending(&mut self) -> BTreeSet<RecordKey> {
        std::mem::take(&mut self.pending)
    }

    pub(super) fn replace(&mut self, key: RecordKey, body: Option<&[u8]>) {
        self.malformed_files.remove(&key);
        if let Some(old) = self.records.remove(&key) {
            for span in old {
                let bucket_id = (span.0 >> 16) as u16;
                let bucket = self.buckets.get_mut(&bucket_id).unwrap();
                let count = bucket.ends.get_mut(&span).unwrap();
                *count -= 1;
                if *count == 0 {
                    bucket.ends.remove(&span);
                    if bucket.max_end == span.1 {
                        bucket.max_end = bucket.ends.keys().map(|span| span.1).max().unwrap_or(0);
                    }
                }
                if bucket.ends.is_empty() {
                    self.buckets.remove(&bucket_id);
                }
            }
        }
        let Some(body) = body else { return };
        #[cfg(test)]
        {
            self.decoded_records += 1;
        }
        if body.len() >= 2 && body[..2] == 2i16.to_be_bytes() && body.len() != 248 {
            self.malformed_files.insert(key.clone());
        }
        if body.len() < 248 || body[..2] != 2i16.to_be_bytes() {
            return;
        }
        let mut spans = Vec::new();
        // Both forks' eight inline extent descriptors. Decode exactly the
        // same starts/counts as ForkData; keep duplicate and overlapping owners.
        for fork in [88, 168] {
            for offset in (fork + 16..fork + 80).step_by(8) {
                let start = u32::from_be_bytes(body[offset..offset + 4].try_into().unwrap());
                let count = u32::from_be_bytes(body[offset + 4..offset + 8].try_into().unwrap());
                if count == 0 {
                    continue;
                }
                let span = (start, u64::from(start) + u64::from(count));
                let bucket = self.buckets.entry((start >> 16) as u16).or_default();
                *bucket.ends.entry(span).or_default() += 1;
                bucket.max_end = bucket.max_end.max(span.1);
                spans.push(span);
            }
        }
        if !spans.is_empty() {
            self.records.insert(key, spans);
        }
    }

    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.overlaps_excluding(start, end, None)
    }

    pub(super) fn malformed_file_except(&self, excluded: &RecordKey) -> bool {
        self.malformed_files.iter().any(|key| key != excluded)
    }

    pub(super) fn overlaps_excluding(
        &self,
        start: u64,
        end: u64,
        excluded: Option<&RecordKey>,
    ) -> bool {
        // Preserve the original descriptor predicate even for a zero-count
        // query: a point strictly inside another fork is still a collision.
        if start > end || end == 0 {
            return false;
        }
        let last_bucket = ((end - 1) >> 16).min(u64::from(u16::MAX)) as u16;
        let excluded_spans = excluded.and_then(|key| self.records.get(key));
        self.buckets.range(..=last_bucket).any(|(_, bucket)| {
            bucket.max_end > start
                && bucket.ends.iter().any(|(&(low, high), &owners)| {
                    u64::from(low) < end
                        && high > start
                        && owners
                            > excluded_spans.map_or(0, |spans| {
                                spans.iter().filter(|&&span| span == (low, high)).count()
                            })
                })
        })
    }
}
