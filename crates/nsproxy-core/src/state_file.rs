use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fs4::fs_std::FileExt;
use serde::{de::DeserializeOwned, Serialize};
use tracing::warn;

pub trait SimpleCRDT: Serialize + DeserializeOwned + Sized {
    fn field_updated(&self) -> u128;
    fn set_field_updated(&mut self, updated_at_ns: u128);

    fn merge(self, other: Self) -> Self {
        let retained_timestamp = self.field_updated();
        let incoming_timestamp = other.field_updated();
        if incoming_timestamp > retained_timestamp {
            other
        } else {
            warn!(
                retained_updated_at_ns = %retained_timestamp,
                rejected_updated_at_ns = %incoming_timestamp,
                "rejected state because it is not newer than the retained state"
            );
            self
        }
    }
}

pub fn read<T: SimpleCRDT>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("reading state file {}", path.display()))?;
    Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
        format!("parsing state file {}", path.display())
    })?))
}

pub fn update<T, F>(path: &Path, update: F) -> Result<T>
where
    T: SimpleCRDT + Default,
    F: FnOnce(&mut T),
{
    try_update(path, |state| {
        update(state);
        Ok(())
    })
}

pub fn try_update<T, F>(path: &Path, update: F) -> Result<T>
where
    T: SimpleCRDT + Default,
    F: FnOnce(&mut T) -> Result<()>,
{
    let parent = path.parent().context("state file path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating state directory {}", parent.display()))?;

    let lock_path = lock_path(path);
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening state lock {}", lock_path.display()))?;
    lock.lock_exclusive()
        .with_context(|| format!("locking state file {}", path.display()))?;

    let existed = path.exists();
    let mut state = read(path)?.unwrap_or_default();
    let old_bytes = serde_json::to_vec(&state).context("serializing current state file")?;
    if let Err(err) = update(&mut state) {
        warn!(
            path = %path.display(),
            error = %err,
            "rejected state update"
        );
        return Err(err).with_context(|| format!("updating state file {}", path.display()));
    }
    let new_bytes = serde_json::to_vec(&state).context("serializing updated state file")?;
    if existed && old_bytes == new_bytes && state.field_updated() != 0 {
        return Ok(state);
    }

    let next_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    state.set_field_updated(next_timestamp.max(state.field_updated().saturating_add(1)));

    let tmp_path = temporary_path(path);
    let bytes = serde_json::to_vec_pretty(&state).context("serializing state file")?;
    let mut tmp = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp_path)
        .with_context(|| format!("opening temporary state file {}", tmp_path.display()))?;
    tmp.write_all(&bytes)
        .with_context(|| format!("writing temporary state file {}", tmp_path.display()))?;
    tmp.sync_all()
        .with_context(|| format!("syncing temporary state file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("replacing state file {}", path.display()))?;
    Ok(state)
}

pub fn append_wal_record(path: &Path, boot_marker: &Path, record: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("WAL path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating WAL directory {}", parent.display()))?;
    let lock_path = boot_marker.with_extension("lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening WAL lock {}", lock_path.display()))?;
    lock.lock_exclusive()
        .with_context(|| format!("locking WAL {}", path.display()))?;

    let boot_id = nsproxy_common::current_boot_id()?;
    if fs::read_to_string(boot_marker).ok().as_deref() != Some(&boot_id) {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?
            .sync_all()?;
        fs::write(boot_marker, boot_id)?;
    }

    let mut wal = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening WAL {}", path.display()))?;
    serde_json::to_writer(&mut wal, record).context("serializing WAL record")?;
    wal.write_all(b"\n")
        .with_context(|| format!("appending WAL record to {}", path.display()))?;
    wal.sync_data()
        .with_context(|| format!("syncing WAL {}", path.display()))?;
    Ok(())
}

pub fn read_wal<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("opening WAL {}", path.display())),
    };
    BufReader::new(file)
        .lines()
        .enumerate()
        .filter_map(|(line_no, line)| match line {
            Ok(line) if line.trim().is_empty() => None,
            Ok(line) => {
                Some(serde_json::from_str(&line).with_context(|| {
                    format!("parsing WAL {} line {}", path.display(), line_no + 1)
                }))
            }
            Err(error) => {
                Some(Err(error).with_context(|| {
                    format!("reading WAL {} line {}", path.display(), line_no + 1)
                }))
            }
        })
        .collect()
}

fn lock_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}lock",
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ))
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension("tmp")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    use super::{append_wal_record, read, read_wal, try_update, update, SimpleCRDT};

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    struct TestState {
        updated_at_ns: u128,
        entries: Vec<String>,
    }

    impl SimpleCRDT for TestState {
        fn field_updated(&self) -> u128 {
            self.updated_at_ns
        }

        fn set_field_updated(&mut self, updated_at_ns: u128) {
            self.updated_at_ns = updated_at_ns;
        }
    }

    #[test]
    fn timestamped_values_merge_by_timestamp() {
        let earlier = TestState {
            updated_at_ns: 10,
            entries: vec!["old".into()],
        };
        let later = TestState {
            updated_at_ns: 11,
            entries: vec!["new".into()],
        };
        assert_eq!(earlier.merge(later.clone()), later);
    }

    #[test]
    fn merge_rejects_stale_and_tied_states() {
        let retained = TestState {
            updated_at_ns: 11,
            entries: vec!["retained".into()],
        };
        for timestamp in [10, 11] {
            let rejected = TestState {
                updated_at_ns: timestamp,
                entries: vec!["rejected".into()],
            };
            assert_eq!(retained.clone().merge(rejected), retained);
        }
    }

    #[test]
    fn failed_update_is_rejected_without_persisting_partial_changes() {
        let path = std::env::temp_dir().join(format!(
            "sp-state-file-rejected-update-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let original = update(&path, |state: &mut TestState| {
            state.entries.push("original".into())
        })
        .unwrap();

        let result = try_update(&path, |state: &mut TestState| {
            state.entries.push("rejected".into());
            Err(anyhow::anyhow!("invalid state"))
        });

        assert!(result.is_err());
        assert_eq!(read::<TestState>(&path).unwrap(), Some(original));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.lock"));
    }

    #[test]
    fn updates_are_persisted_with_monotonic_timestamps() {
        let path = std::env::temp_dir().join(format!("sp-state-file-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.lock"));
        let first = update(&path, |state: &mut TestState| {
            state.entries.push("one".into())
        })
        .unwrap();
        let second = update(&path, |state: &mut TestState| {
            state.entries.push("two".into())
        })
        .unwrap();
        assert!(second.field_updated() > first.field_updated());
        assert_eq!(second.entries, ["one", "two"]);
        assert_eq!(read::<TestState>(&path).unwrap(), Some(second));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.lock"));
    }

    #[test]
    fn initializes_missing_timestamp_on_unchanged_state() {
        let path = std::env::temp_dir().join(format!(
            "sp-state-file-uninitialized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.lock"));
        let initial = TestState {
            updated_at_ns: 0,
            entries: vec!["existing".into()],
        };
        fs::write(&path, serde_json::to_vec(&initial).unwrap()).unwrap();

        let updated = update(&path, |_: &mut TestState| {}).unwrap();

        assert!(updated.field_updated() > 0);
        assert_eq!(read::<TestState>(&path).unwrap(), Some(updated));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.lock"));
    }

    #[test]
    fn wal_appends_and_reads_records() {
        let base = std::env::temp_dir().join(format!("sp-wal-{}", std::process::id()));
        let wal = base.join("events.jsonl");
        let boot = base.join("events.boot");
        let _ = fs::remove_dir_all(&base);

        append_wal_record(&wal, &boot, &serde_json::json!({"n": 1})).unwrap();
        append_wal_record(&wal, &boot, &serde_json::json!({"n": 2})).unwrap();

        let records: Vec<Value> = read_wal(&wal).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["n"], 1);
        assert_eq!(records[1]["n"], 2);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn wal_serializes_concurrent_appenders() {
        let base = std::env::temp_dir().join(format!("sp-wal-concurrent-{}", std::process::id()));
        let wal = Arc::new(base.join("events.jsonl"));
        let boot = Arc::new(base.join("events.boot"));
        let _ = fs::remove_dir_all(&base);

        let writers = (0..8)
            .map(|writer| {
                let wal = Arc::clone(&wal);
                let boot = Arc::clone(&boot);
                std::thread::spawn(move || {
                    for sequence in 0..20 {
                        append_wal_record(
                            &wal,
                            &boot,
                            &serde_json::json!({"writer": writer, "sequence": sequence}),
                        )
                        .unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }

        let records: Vec<Value> = read_wal(&wal).unwrap();
        assert_eq!(records.len(), 160);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn wal_reports_malformed_records() {
        let path =
            std::env::temp_dir().join(format!("sp-wal-malformed-{}.jsonl", std::process::id()));
        fs::write(&path, "{\"ok\":true}\nnot-json\n").unwrap();
        assert!(read_wal::<Value>(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
