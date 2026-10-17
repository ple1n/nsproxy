use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct MoveEntry {
    source: PathBuf,
    destination: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct MovePlan {
    links: Vec<PathBuf>,
    entries: Vec<MoveEntry>,
}

const MOVE_PLAN_FILE: &str = ".nsproxy-migration-plan.json";

pub fn stage_state_root(source: &Path, target: &Path) -> Result<()> {
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalizing source state root {}", source.display()))?;
    let target_parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(target_parent)?;
    let target = target_parent.canonicalize()?.join(
        target
            .file_name()
            .context("target state root must have a final path component")?,
    );
    ensure!(
        source != target,
        "source and target state roots must differ"
    );
    ensure!(
        !target.starts_with(&source),
        "target state root must not be inside the source state root"
    );
    ensure!(
        !target.exists() || fs::read_dir(&target)?.next().is_none(),
        "target state root {} must be missing or empty",
        target.display()
    );
    fs::create_dir_all(&target)
        .with_context(|| format!("creating target state root {}", target.display()))?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o777))
        .with_context(|| format!("setting target state root permissions {}", target.display()))?;

    for entry in fs::read_dir(&source)
        .with_context(|| format!("reading source state root {}", source.display()))?
    {
        let entry = entry?;
        let source_path = entry.path();
        if is_socket(&source_path)? {
            continue;
        }
        let target_path = target.join(entry.file_name());
        ensure!(
            !target_path.exists() && fs::symlink_metadata(&target_path).is_err(),
            "target entry {} already exists",
            target_path.display()
        );
        symlink(&source_path, &target_path).with_context(|| {
            format!(
                "linking staged state {} to {}",
                target_path.display(),
                source_path.display()
            )
        })?;
    }
    Ok(())
}

pub fn finish_state_root(root: &Path, rootfs_root: &Path) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalizing staged state root {}", root.display()))?;
    let rootfs_root = canonicalize_target(rootfs_root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
        .with_context(|| format!("setting state root permissions {}", root.display()))?;

    let plan_path = root.join(MOVE_PLAN_FILE);
    let plan = match fs::symlink_metadata(&plan_path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "migration plan {} is not a regular file",
                plan_path.display()
            );
            serde_json::from_slice::<MovePlan>(
                &fs::read(&plan_path)
                    .with_context(|| format!("reading migration plan {}", plan_path.display()))?,
            )
            .with_context(|| format!("parsing migration plan {}", plan_path.display()))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut links = Vec::new();
            let mut entries = Vec::new();
            for entry in fs::read_dir(&root)
                .with_context(|| format!("reading staged state root {}", root.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                let is_symlink = metadata.file_type().is_symlink();
                if is_symlink {
                    links.push(path.clone());
                }
                if !is_symlink && entry.file_name() != "rootfs" {
                    continue;
                }

                let source = if is_symlink {
                    fs::read_link(&path)?
                } else {
                    path.clone()
                };
                if is_socket(&source)? {
                    continue;
                }
                let destination = if entry.file_name() == "rootfs" {
                    rootfs_root.clone()
                } else {
                    path
                };
                entries.push(MoveEntry {
                    source,
                    destination,
                });
            }
            let plan = MovePlan { links, entries };
            validate_move_plan(&root, &rootfs_root, &plan)?;
            if !plan.links.is_empty() || !plan.entries.is_empty() {
                write_move_plan(&plan_path, &plan)?;
            }
            plan
        }
        Err(error) => return Err(error.into()),
    };

    for link in &plan.links {
        match fs::symlink_metadata(link) {
            Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(link)
                .with_context(|| format!("removing staged migration link {}", link.display()))?,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    for entry in &plan.entries {
        let source_exists = path_exists(&entry.source)?;
        let destination_exists = path_exists(&entry.destination)?;
        match (source_exists, destination_exists) {
            (false, true) => continue,
            (false, false) => anyhow::bail!(
                "both migration source {} and destination {} are missing",
                entry.source.display(),
                entry.destination.display()
            ),
            (true, _) => move_path(&entry.source, &entry.destination).with_context(|| {
                format!(
                    "moving migration source {} to {}",
                    entry.source.display(),
                    entry.destination.display()
                )
            })?,
        }
    }
    remove_previous_temporary_copies(&root, &plan)?;
    if plan_path.exists() {
        fs::remove_file(&plan_path).with_context(|| {
            format!("removing completed migration plan {}", plan_path.display())
        })?;
    }
    Ok(())
}

fn remove_previous_temporary_copies(root: &Path, plan: &MovePlan) -> Result<()> {
    let source_names = plan
        .entries
        .iter()
        .filter_map(|entry| entry.source.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect::<std::collections::HashSet<_>>();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(suffix) = name.strip_prefix(".migration-") else {
            continue;
        };
        let Some((pid, source_name)) = suffix.split_once('-') else {
            continue;
        };
        if pid.parse::<u32>().is_err() || !source_names.contains(source_name) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(&path).with_context(|| {
                format!("removing incomplete migration copy {}", path.display())
            })?;
        } else {
            fs::remove_file(&path).with_context(|| {
                format!("removing incomplete migration copy {}", path.display())
            })?;
        }
    }
    Ok(())
}

pub fn validate_removable_state_root(source: &Path, target: &Path) -> Result<PathBuf> {
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalizing source state root {}", source.display()))?;
    let target_name = target
        .file_name()
        .context("target state root must have a final path component")?;
    let target_parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let target = target_parent
        .canonicalize()
        .with_context(|| format!("canonicalizing target parent {}", target_parent.display()))?
        .join(target_name);

    ensure!(
        source != target && !target.starts_with(&source) && !source.starts_with(&target),
        "source and target state roots must be separate"
    );
    let metadata = fs::symlink_metadata(&target)
        .with_context(|| format!("reading target state root {}", target.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "target {} is not a state-root directory",
        target.display()
    );
    Ok(target)
}

pub fn remove_state_root(source: &Path, target: &Path) -> Result<()> {
    let target = validate_removable_state_root(source, target)?;
    crate::sys::remove_path_recursive(&target)
        .with_context(|| format!("removing state root {}", target.display()))
}

fn is_socket(path: &Path) -> Result<bool> {
    let link_metadata = fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_socket() {
        return Ok(true);
    }
    if !link_metadata.file_type().is_symlink() {
        return Ok(false);
    }
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_socket()),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn canonicalize_target(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent
        .canonicalize()
        .with_context(|| format!("canonicalizing destination parent {}", parent.display()))?
        .join(
            path.file_name()
                .context("migration destination must have a final path component")?,
        ))
}

fn validate_move_plan(root: &Path, rootfs_root: &Path, plan: &MovePlan) -> Result<()> {
    let staged_links = plan.links.iter().collect::<std::collections::HashSet<_>>();
    for entry in &plan.entries {
        ensure!(
            entry.source.is_absolute(),
            "migration source {} is not an absolute path",
            entry.source.display()
        );
        let source_parent = entry
            .source
            .parent()
            .context("migration source must have a parent directory")?
            .canonicalize()
            .with_context(|| {
                format!(
                    "canonicalizing migration source parent {}",
                    entry.source.parent().unwrap().display()
                )
            })?;
        let source = source_parent.join(
            entry
                .source
                .file_name()
                .context("migration source must have a final path component")?,
        );
        ensure!(
            !source.starts_with(root) && !root.starts_with(&source),
            "migration source {} overlaps target state root {}",
            source.display(),
            root.display()
        );
        ensure!(
            source != entry.destination,
            "migration source and destination are the same path: {}",
            source.display()
        );
        let source_metadata = fs::symlink_metadata(&source)
            .with_context(|| format!("reading migration source {}", source.display()))?;
        if entry.destination == rootfs_root {
            ensure!(
                source_metadata.is_dir() && !source_metadata.file_type().is_symlink(),
                "legacy rootfs {} must be a real directory",
                source.display()
            );
            match fs::symlink_metadata(&entry.destination) {
                Ok(destination_metadata) => ensure!(
                    destination_metadata.is_dir() && !destination_metadata.file_type().is_symlink(),
                    "rootfs destination {} exists and is not a real directory",
                    entry.destination.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            continue;
        }
        match fs::symlink_metadata(&entry.destination) {
            Ok(metadata) if staged_links.contains(&entry.destination) => {
                ensure!(
                    metadata.file_type().is_symlink(),
                    "staged migration entry {} is no longer a symlink",
                    entry.destination.display()
                );
            }
            Ok(_) => anyhow::bail!(
                "migration destination {} already exists",
                entry.destination.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_move_plan(path: &Path, plan: &MovePlan) -> Result<()> {
    let temporary = path.with_file_name(format!(
        ".nsproxy-migration-plan-{}.tmp",
        std::process::id()
    ));
    let bytes = serde_json::to_vec(plan).context("serializing migration plan")?;
    fs::write(&temporary, bytes)
        .with_context(|| format!("writing temporary migration plan {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("installing migration plan {}", path.display()))?;
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn move_path(source: &Path, destination: &Path) -> Result<()> {
    remove_socket_files(source)?;
    let source_metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if path_exists(destination)? {
        let destination_metadata = fs::symlink_metadata(destination)?;
        if source_metadata.is_dir() && destination_metadata.is_dir() {
            return move_directory_contents(source, destination, source_metadata.permissions());
        }
        if source_metadata.is_file()
            && destination_metadata.is_file()
            && files_equal(source, destination)?
        {
            fs::remove_file(source)?;
            return Ok(());
        }
        if source_metadata.file_type().is_symlink()
            && destination_metadata.file_type().is_symlink()
            && fs::read_link(source)? == fs::read_link(destination)?
        {
            fs::remove_file(source)?;
            return Ok(());
        }
        anyhow::bail!(
            "migration destination {} already exists",
            destination.display()
        );
    }
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            move_across_filesystems(source, destination, source_metadata)
        }
        Err(error) => Err(error.into()),
    }
}

fn move_across_filesystems(
    source: &Path,
    destination: &Path,
    metadata: fs::Metadata,
) -> Result<()> {
    if metadata.is_dir() {
        fs::create_dir(destination)?;
        move_directory_contents(source, destination, metadata.permissions())
    } else if metadata.is_file() {
        fs::copy(source, destination)
            .with_context(|| format!("copying regular migration file {}", source.display()))?;
        fs::remove_file(source)?;
        Ok(())
    } else if metadata.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        symlink(&target, destination)?;
        fs::remove_file(source)?;
        Ok(())
    } else {
        anyhow::bail!(
            "cannot move special filesystem entry across filesystems: {}",
            source.display()
        )
    }
}

fn move_directory_contents(
    source: &Path,
    destination: &Path,
    permissions: fs::Permissions,
) -> Result<()> {
    remove_socket_files(source)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        move_path(&entry.path(), &destination.join(entry.file_name()))?;
    }
    fs::set_permissions(destination, permissions)?;
    fs::remove_dir(source)?;
    Ok(())
}

fn remove_socket_files(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_socket() || (metadata.file_type().is_symlink() && is_socket(path)?) {
        fs::remove_file(path)?;
    } else if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            remove_socket_files(&entry?.path())?;
        }
    }
    Ok(())
}

fn files_equal(first: &Path, second: &Path) -> Result<bool> {
    let first_metadata = fs::metadata(first)?;
    let second_metadata = fs::metadata(second)?;
    if first_metadata.len() != second_metadata.len() {
        return Ok(false);
    }
    let mut first_file = fs::File::open(first)?;
    let mut second_file = fs::File::open(second)?;
    let mut first_buffer = [0; 8192];
    let mut second_buffer = [0; 8192];
    loop {
        let first_len = first_file.read(&mut first_buffer)?;
        let second_len = second_file.read(&mut second_buffer)?;
        if first_len != second_len || first_buffer[..first_len] != second_buffer[..second_len] {
            return Ok(false);
        }
        if first_len == 0 {
            return Ok(true);
        }
    }
}

#[cfg(unix)]
fn symlink(source: &Path, target: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(source, target)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    use super::{
        MOVE_PLAN_FILE, MoveEntry, MovePlan, finish_state_root, remove_state_root,
        stage_state_root, validate_removable_state_root,
    };

    #[test]
    fn finishing_moves_state_and_legacy_rootfs_to_their_destinations() {
        let temp = std::env::temp_dir().join(format!(
            "sp-migrate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = temp.join("source");
        let target = temp.join("target");
        let rootfs = temp.join("global-rootfs");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(source.join("rootfs")).unwrap();
        fs::write(source.join("rootfs/image"), "original").unwrap();
        fs::write(source.join("state.json"), "state").unwrap();

        stage_state_root(&source, &target).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o777
        );
        assert!(
            fs::symlink_metadata(target.join("rootfs"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::create_dir_all(target.join(".migration-123-rootfs")).unwrap();
        fs::write(target.join(".migration-123-rootfs/partial"), "partial").unwrap();

        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        finish_state_root(&target, &rootfs).unwrap();
        finish_state_root(&target, &rootfs).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o777
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("image")).unwrap(),
            "original"
        );
        assert!(fs::symlink_metadata(target.join("rootfs")).is_err());
        assert!(fs::symlink_metadata(source.join("rootfs")).is_err());
        assert!(fs::symlink_metadata(target.join(".migration-123-rootfs")).is_err());
        assert_eq!(
            fs::read_to_string(target.join("state.json")).unwrap(),
            "state"
        );
        assert!(fs::symlink_metadata(source.join("state.json")).is_err());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn finishing_resumes_an_interrupted_move_plan() {
        let temp = std::env::temp_dir().join(format!(
            "sp-migrate-resume-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = temp.join("source");
        let target = temp.join("target");
        let rootfs = temp.join("global-rootfs");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("first.json"), "first").unwrap();
        fs::write(source.join("second.json"), "second").unwrap();
        stage_state_root(&source, &target).unwrap();

        fs::remove_file(target.join("first.json")).unwrap();
        fs::rename(source.join("first.json"), target.join("first.json")).unwrap();
        let plan = MovePlan {
            links: vec![target.join("first.json"), target.join("second.json")],
            entries: vec![
                MoveEntry {
                    source: source.join("first.json"),
                    destination: target.join("first.json"),
                },
                MoveEntry {
                    source: source.join("second.json"),
                    destination: target.join("second.json"),
                },
            ],
        };
        fs::write(
            target.join(MOVE_PLAN_FILE),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();

        finish_state_root(&target, &rootfs).unwrap();

        assert_eq!(
            fs::read_to_string(target.join("first.json")).unwrap(),
            "first"
        );
        assert_eq!(
            fs::read_to_string(target.join("second.json")).unwrap(),
            "second"
        );
        assert!(fs::symlink_metadata(source.join("second.json")).is_err());
        assert!(fs::symlink_metadata(target.join(MOVE_PLAN_FILE)).is_err());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn migration_skips_socket_files_at_root_and_inside_directories() {
        let temp = std::env::temp_dir().join(format!(
            "sp-migrate-sockets-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = temp.join("source");
        let target = temp.join("target");
        let rootfs = temp.join("global-rootfs");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("state.json"), "state").unwrap();
        let root_socket = UnixListener::bind(source.join("daemon.sock")).unwrap();
        let nested_socket = UnixListener::bind(source.join("nested/worker.sock")).unwrap();
        symlink(source.join("daemon.sock"), source.join("daemon-link.sock")).unwrap();
        symlink("loop", source.join("nested/loop")).unwrap();

        stage_state_root(&source, &target).unwrap();
        assert!(fs::symlink_metadata(target.join("daemon.sock")).is_err());
        assert!(fs::symlink_metadata(target.join("daemon-link.sock")).is_err());
        symlink(source.join("daemon.sock"), target.join("legacy.sock")).unwrap();

        finish_state_root(&target, &rootfs).unwrap();

        assert!(fs::symlink_metadata(target.join("daemon.sock")).is_err());
        assert!(fs::symlink_metadata(target.join("legacy.sock")).is_err());
        assert!(fs::symlink_metadata(target.join("nested/worker.sock")).is_err());
        assert!(
            fs::symlink_metadata(target.join("nested/loop"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(target.join("state.json")).unwrap(),
            "state"
        );
        assert!(fs::symlink_metadata(source.join("state.json")).is_err());
        assert!(fs::symlink_metadata(source.join("nested")).is_err());

        drop((root_socket, nested_socket));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn staging_refuses_nonempty_target() {
        let temp = std::env::temp_dir().join(format!(
            "sp-migrate-refuse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = temp.join("source");
        let target = temp.join("target");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("keep"), "data").unwrap();
        assert!(stage_state_root(&source, &target).is_err());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn removes_staged_target_with_ui_created_state_without_touching_source() {
        let temp = std::env::temp_dir().join(format!(
            "sp-migrate-rm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = temp.join("source");
        let target = temp.join("target");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("state.json"), "source data").unwrap();
        stage_state_root(&source, &target).unwrap();
        fs::remove_file(target.join("state.json")).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        fs::create_dir(target.join("uplink")).unwrap();
        fs::write(target.join("namespaces.json"), "ui-created state").unwrap();
        assert_eq!(
            validate_removable_state_root(&source, &target).unwrap(),
            target.canonicalize().unwrap()
        );
        remove_state_root(&source, &target).unwrap();
        assert!(!target.exists());
        assert_eq!(
            fs::read_to_string(source.join("state.json")).unwrap(),
            "source data"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn refuses_to_remove_source_or_parent_target() {
        let temp = std::env::temp_dir().join(format!(
            "sp-migrate-rm-refuse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = temp.join("source");
        let target = temp.join("target");
        let rootfs = temp.join("global-rootfs");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("state.json"), "source data").unwrap();
        stage_state_root(&source, &target).unwrap();
        finish_state_root(&target, &rootfs).unwrap();

        assert!(remove_state_root(&source, &source).is_err());
        assert!(remove_state_root(&source, &temp).is_err());
        assert_eq!(
            fs::read_to_string(target.join("state.json")).unwrap(),
            "source data"
        );
        assert!(fs::symlink_metadata(source.join("state.json")).is_err());
        fs::remove_dir_all(temp).unwrap();
    }
}
