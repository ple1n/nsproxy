use std::collections::{BTreeSet, HashMap, VecDeque};
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cargo_lock::{Lockfile, package::Package as LockPackage};
use cargo_metadata::{DependencyKind, MetadataCommand, Node, Package, PackageId};
use walkdir::WalkDir;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let metadata = MetadataCommand::new().current_dir(&manifest_dir).exec()?;

    let root_pkg = metadata
        .packages
        .iter()
        .find(|pkg| pkg.manifest_path.as_std_path() == manifest_dir.join("Cargo.toml"))
        .ok_or("failed to locate root package for nsproxy-core")?;

    let closure = dependency_closure(root_pkg, &metadata.packages, metadata.resolve.as_ref())?;
    let package_refs: Vec<&Package> = metadata.packages.iter().collect();
    let local_pkgs = closure.local_packages(&package_refs);
    let files = collect_hash_inputs(&local_pkgs, metadata.workspace_root.as_std_path());
    let lock_path = metadata.workspace_root.as_std_path().join("Cargo.lock");
    let registry_inputs = lock_registry_inputs(&closure, &metadata.packages, &lock_path)?;
    let tree_hash = hash_inputs(&files, &registry_inputs, metadata.workspace_root.as_std_path())?;

    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed={}", lock_path.display());

    let epoch_secs = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or_else(now_epoch_secs);

    println!("cargo:rustc-env=NSP_BUILD_TREE_HASH={tree_hash}");
    println!("cargo:rustc-env=NSP_BUILD_EPOCH_SECS={epoch_secs}");

    Ok(())
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct DepClosure {
    all_ids: BTreeSet<PackageId>,
    local_ids: BTreeSet<PackageId>,
}

impl DepClosure {
    fn local_packages<'a>(&self, packages: &'a [&'a Package]) -> Vec<&'a Package> {
        let mut local = Vec::new();
        for pkg in packages {
            if self.local_ids.contains(&pkg.id) {
                local.push(*pkg);
            }
        }
        local.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.manifest_path.cmp(&b.manifest_path)));
        local
    }
}

fn dependency_closure(
    root_pkg: &Package,
    packages: &[Package],
    resolve: Option<&cargo_metadata::Resolve>,
) -> Result<DepClosure, Box<dyn Error>> {
    let resolve = resolve.ok_or("cargo metadata resolve graph missing")?;

    let packages_by_id: HashMap<&PackageId, &Package> =
        packages.iter().map(|pkg| (&pkg.id, pkg)).collect();
    let nodes_by_id: HashMap<&PackageId, &Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();

    let mut queue = VecDeque::new();
    let mut visited: BTreeSet<PackageId> = BTreeSet::new();

    queue.push_back(root_pkg.id.clone());

    while let Some(pkg_id) = queue.pop_front() {
        if !visited.insert(pkg_id.clone()) {
            continue;
        }

        let Some(node) = nodes_by_id.get(&pkg_id) else {
            continue;
        };

        for dep in &node.deps {
            let include_dep = dep.dep_kinds.iter().any(|kind| match kind.kind {
                DependencyKind::Normal | DependencyKind::Build => true,
                DependencyKind::Development => false,
                _ => false,
            });
            if include_dep {
                queue.push_back(dep.pkg.clone());
            }
        }
    }

    let mut local_ids = BTreeSet::new();
    for pkg_id in &visited {
        let Some(pkg) = packages_by_id.get(&pkg_id) else {
            continue;
        };
        // Local path/workspace packages are not checksummed in Cargo.lock.
        if pkg.source.is_none() {
            local_ids.insert((*pkg_id).clone());
        }
    }

    Ok(DepClosure {
        all_ids: visited,
        local_ids,
    })
}

fn collect_hash_inputs(packages: &[&Package], workspace_root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for pkg in packages {
        let pkg_root = pkg
            .manifest_path
            .as_std_path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| workspace_root.to_path_buf());

        let manifest = pkg_root.join("Cargo.toml");
        if manifest.exists() {
            files.push(manifest);
        }

        let build_rs = pkg_root.join("build.rs");
        if build_rs.exists() {
            files.push(build_rs);
        }

        let src_dir = pkg_root.join("src");
        if src_dir.exists() {
            files.extend(walk_files(&src_dir));
        }
    }

    files.sort();
    files.dedup();
    files
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| !is_ignored(entry.path()))
        .map(|entry| entry.into_path())
        .collect()
}

fn is_ignored(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str() == OsStr::new("target") || c.as_os_str() == OsStr::new(".git"))
}

fn lock_registry_inputs(
    closure: &DepClosure,
    packages: &[Package],
    lock_path: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let lock = Lockfile::load(lock_path)?;
    let by_name_ver_source: HashMap<(String, String, Option<String>), &LockPackage> = lock
        .packages
        .iter()
        .map(|pkg| {
            (
                (
                    pkg.name.to_string(),
                    pkg.version.to_string(),
                    pkg.source.as_ref().map(|s| s.to_string()),
                ),
                pkg,
            )
        })
        .collect();

    let package_map: HashMap<&PackageId, &Package> =
        packages.iter().map(|pkg| (&pkg.id, pkg)).collect();

    let mut out = Vec::new();
    for pkg_id in &closure.all_ids {
        let Some(pkg) = package_map.get(pkg_id) else {
            continue;
        };
        if pkg.source.is_none() {
            continue;
        }

        let source = pkg.source.as_ref().map(|s| s.to_string());
        let key = (pkg.name.to_string(), pkg.version.to_string(), source.clone());
        let lock_match = by_name_ver_source.get(&key);

        let checksum = lock_match
            .and_then(|p| p.checksum.as_ref().map(|c| c.to_string()))
            .unwrap_or_else(|| "none".to_string());

        out.push(format!(
            "{}|{}|{}|{}",
            pkg.name,
            pkg.version,
            source.unwrap_or_else(|| "none".to_string()),
            checksum
        ));
    }

    out.sort();
    out.dedup();
    Ok(out)
}

fn hash_inputs(
    files: &[PathBuf],
    registry_inputs: &[String],
    workspace_root: &Path,
) -> Result<String, Box<dyn Error>> {
    let mut hasher = blake3::Hasher::new();

    for entry in registry_inputs {
        hasher.update(entry.as_bytes());
        hasher.update(&[0u8]);
    }

    for path in files {
        let rel = path.strip_prefix(workspace_root).unwrap_or(path);
        let bytes = fs::read(path)?;
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&[0u8]);
        hasher.update(&bytes);
        hasher.update(&[0u8]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}
