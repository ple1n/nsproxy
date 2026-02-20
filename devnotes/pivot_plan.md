# Pivot Root Sandbox — Implementation Plan

## Context

- nsproxy runs SUID root; full capabilities available in both parent (out-ns) and child (in-ns) processes
- Two-process model: parent stays in host ns, child enters/becomes the new ns
- All instance state lives under `/nsp3/<profile>/` (configurable via `PERSIST_ROOT`)
- Overlay mode (existing, working, **do not touch**): bind-mounts layered onto real `/` inside a new mount namespace
- Pivot mode (new): proper root replacement via `pivot_root(2)` with a tmpfs staging area

---

## Core Decision: Always Mount tmpfs

**Always** mount a fresh tmpfs at `rootfs.root` before constructing the pivot root. No `tmpfs: bool` flag needed — it is unconditional.

Rationale: same as how initramfs works. The staging directory is anonymous, can't be tampered from outside, disappears on unmount, and lets us construct the new root from scratch with correct ownership at every step.

**Remove `tmpfs: bool` from `ProfileRootfs`.**

---

## Symlink Layout (this distro: Arch/Fedora-style)

```
/bin  -> usr/bin   (symlink, not a dir)
/lib  -> usr/lib
/lib64 -> usr/lib
/sbin -> usr/bin
```

Only `/usr` needs to be bind-mounted. Then we create the four symlinks in the tmpfs root. `/etc` is a real directory and must be bind-mounted separately.

**Question to verify before impl:** does the target distro also use usr-merge? Check with `[ -L /bin ] && echo merged`. Plan must handle both merged and non-merged layouts.

---

## Skeleton Construction Sequence (child, in new mount ns)

```
1. mount("tmpfs", rootfs.root, ...)            -- staging area
2. stat each source dir, mkdir at dest          -- preserve uid/gid/mode
3. mount_bind_ro_explicit(host, new_root/host)  -- /usr /etc
4. symlink("usr/bin",  new_root/bin)            -- if merged
   symlink("usr/lib",  new_root/lib)
   symlink("usr/lib",  new_root/lib64)
   symlink("usr/bin",  new_root/sbin)
5. mount procfs at new_root/proc               -- fresh, represents new pid ns
6. mount sysfs at new_root/sys                 -- fresh
7. mount tmpfs at new_root/tmp  mode=1777      -- writable scratch
8. mount tmpfs at new_root/run  mode=755       -- fresh runtime dir
9. mkdir new_root/run/user/<uid>  (from stat)  -- preserve uid ownership
10. apply TemplateConfig.mounts into new_root  -- user-declared binds
11. apply TemplateConfig.chmod                 -- ownership fixups
12. mkdir new_root/nsp3 + bind /nsp3           -- instance state accessible inside
13. pivot_root_into(new_root, put_old)
14. chdir("/")
15. umount2(put_old, MNT_DETACH)
```

**Ownership rule:** before every `mkdir` for a bind-mount point, `stat()` the source and create the dir with matching `mode/uid/gid` via `chown`. This replaces the current approach of just calling `ensure_mount_target`.

---

## Potential Problems / Open Questions

| Problem | Mitigation |
|---|---|
| `/dev`: fresh tmpfs has no devices | Bind-mount specific nodes from host `/dev`: `null zero full random urandom tty ptmx` + symlinks `fd stdin stdout stderr` |
| `/dev/pts` needed for terminal | Mount devpts fresh inside new root |
| Merged-usr vs non-merged distros | Detect at runtime with `std::fs::symlink_metadata`, create symlinks only if source is a symlink on host |
| `/etc/resolv.conf` is often a symlink to `/run/systemd/resolve/stub-resolv.conf` | Follow and bind the real file, or bind `/run/systemd/resolve` as part of default run mounts |
| App writes to `/nsp3/<profile>/` for config | Step 12 above: bind-mount `/nsp3` into new root at same path |
| Wayland/pipewire/pulse sockets in `/run/user/$UID/` | These go into `TemplateConfig.mounts` or `HotConfig.mnt`, not auto-skeleton |
| `pivot_root` requires new_root to be a mount point | tmpfs mount satisfies this |
| `put_old` must be under new_root | Use `new_root/.pivot_old` created just before pivot, removed after detach |
| `/proc/self` resolves to old proc before pivot | Mount fresh procfs early enough, after pivot it auto-reflects new pid ns |
| Instance root path must exist inside new ns | Step 12 ensures it |
| nswrap/nsproxy binary must be reachable inside for re-exec | Bind `/nsp3/` covers `nswrap` binary if it lives there; otherwise bind the binary explicitly |

---

## TemplateConfig Changes (lib.rs)

- Rename `ProfileConfig` → `TemplateConfig` everywhere
- Remove `tmpfs: bool` from `ProfileRootfs`
- `ProfileRootfs.put_old` stays — set to `Some("/.pivot_old")` by default in template generator
- Add `skeleton: Option<Vec<SkeletonEntry>>` to `ProfileRootfs`:
  ```
  enum SkeletonEntry { Bind(PathBuf), Tmpfs(PathBuf), Proc(PathBuf), Sys(PathBuf), Dev(PathBuf) }
  ```
  `None` = use the hard-coded default above. Lets advanced users override (e.g. skip `/sys`).

---

## sandbox.rs — New Function

```rust
pub fn apply_pivot(template: &TemplateConfig) -> Result<()>
```

Self-contained, calls nothing from the Overlay path. Steps:
1. `mount_tmpfs(rootfs.root)`
2. `build_skeleton(&rootfs)` — steps 2–9 above
3. `apply_mounts_into(rootfs.root, &template.mounts)` — adapted from `apply_mounts` but targets new root
4. `apply_chmod(rootfs.root, &template.chmod)`
5. `ensure_instance_root_inside(rootfs.root)` — step 12
6. `pivot_root_into(rootfs.root, put_old)`

---

## sys.rs — New Helpers Needed

- `mount_tmpfs(path, mode, uid, gid)`
- `mount_procfs(path)`
- `mount_sysfs(path)`
- `mount_devtmpfs(path)` — minimal device nodes
- `create_dir_like_source(src, dst)` — mkdir at dst with uid/gid/mode from `stat(src)`

---

## GUI: Sandbox Tab Mount Trees

Two columns side by side (`egui::SidePanel`):

**Left — Source (host):** group all `TemplateConfig.mounts` sources by parent dir prefix, `CollapsingHeader` per parent, leaf = `filename → dest`

**Right — Destination (sandbox root):** same mount list keyed by destination, show root label as `rootfs.root` value. Merge `HotConfig.mnt` entries with `[hot]` badge. Both trees built at render time, no extra data structure.

---

## Files to Change

| File | Change |
|---|---|
| `crates/nsproxy-core/src/lib.rs` | Rename `ProfileConfig→TemplateConfig`, remove `tmpfs`, add `SkeletonEntry` |
| `crates/nsproxy-core/src/sandbox.rs` | Add `apply_pivot`, `build_skeleton`, helpers |
| `crates/nsproxy-core/src/sys.rs` | Add `mount_tmpfs`, `mount_procfs`, `mount_sysfs`, `mount_devtmpfs`, `create_dir_like_source` |
| `crates/nsproxy-core/src/bin/nsproxy.rs` | Call `apply_pivot` in child branches of `cmd_run`/`Up`; rename usages |
| `crates/nsproxy-ui/src/main.rs` | Add Sandbox tab with mount trees |
| `profiles/vscode.json` | Update field names |

---

## Test Plan

```bash
# 1. Compile check
cargo check -p nsproxy-core -p nsproxy-ui

# 2. Overlay regression
nsproxy up vscode   # must work exactly as before

# 3. Minimal pivot test profile
# profile: rootfs.mode=Pivot, rootfs.root=/tmp/nsptest, no extra mounts
nsproxy up pivot_test
# inside: ls /usr /etc /proc /dev/null — must all exist
# inside: id  — must show correct uid
# inside: cat /etc/resolv.conf  — must resolve

# 4. VScode pivot profile
# adapted vscode.json with mode=Pivot
nsproxy up vscode_pivot
# code . must launch
```


# Separation of concerns


For now, `sp serve` current sets up bind mounts a lot of things and start a TUN serving process, `sp up` just unshares as much as possible and keep a daemon to keep the namespaces alive. 

We will need a `sp sandbox` that should do some one off work (if first launch), work exclusively about pivot, bind mount sandboxing related things, and watches hotconfig file for changes. 

The changes about mounts and pivot are associated with the mount namespace. not any process, so we can do that.

the pivot root will be always done at /tmp/ or /run/ or equivalent to minimzie dependency on a speciific filesystem. 

by default sandboxed app state will be, stored at /nsp3/{profile_name}/... state folders (nsp3 is a configurable root). they will be mounted into the pivot root within /tmp. 

we want users to be free to choose where state is stored to avoid disk running out etc situation giving more flexibility.

for now, there should be a toggle in the config such that the user either mounts DBus or not mount DBus. DBus is a major security vector.

# GUI

as opposed to Firejail or bubblejail, and unix philosophy, the GUI should be holistic, exhaustive, visualizing all that can be seen by a program within the mount namespace. 


working demo
```rust
MainCommand::Sandbox { sargs } => {
            // ----------------------------------------------------------------
            // Minimal pivot-root sandbox demo.
            // No config files are read.  We just:
            //   1. unshare a fresh mount namespace
            //   2. build a tmpfs new-root with essential bind-mounts
            //   3. pivot_root into it
            //   4. drop into a shell
            // Requires CAP_SYS_ADMIN (i.e. run via `sp sandbox` / as root).
            // ----------------------------------------------------------------
            check_capsys()?;

            // Resolve shell preferences now, before any namespace changes that
            // might affect uid lookups or the $PATH environment.
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(sargs);
            shell_prefs.adjust()?;

            let pid = std::process::id();
            let new_root = PathBuf::from(format!("/tmp/nsp_sandbox_{}", pid));
            let put_old = new_root.join(".old");

            // Step 1: enter a new, private mount namespace.
            unshare(CloneFlags::CLONE_NEWNS)?;
            // Make every existing mount private so our changes don't leak out.
            mount_bind_root()?;

            // Step 2: mount tmpfs as the staging root.
            mount_tmpfs(&new_root)?;

            // Step 3: create stub directories inside the new root.
            for d in &[
                "usr", "etc", "dev", "proc", "sys", "tmp", "run", "home", "root",
            ] {
                std::fs::create_dir_all(new_root.join(d))?;
            }

            // Step 4: bind-mount /usr and /etc read-only (recursive).
            for dir in &["usr", "etc"] {
                let src = PathBuf::from(format!("/{}", dir));
                if src.exists() {
                    mount_bind_ro_explicit(&src, &new_root.join(dir), true)?;
                }
            }

            // Step 5: recreate merged-usr symlinks (/bin /lib /lib64 /sbin ->
            // usr/…) if the host uses usr-merge, otherwise bind-mount them.
            for link in &["bin", "lib", "lib64", "lib32", "sbin"] {
                let host_path = PathBuf::from(format!("/{}", link));
                let dst = new_root.join(link);
                if let Ok(target) = std::fs::read_link(&host_path) {
                    // It's a symlink on the host — recreate inside new root.
                    if !dst.exists() {
                        let _ = std::os::unix::fs::symlink(&target, &dst);
                    }
                } else if host_path.is_dir() {
                    // Real directory — bind-mount it.
                    std::fs::create_dir_all(&dst)?;
                    mount_bind_ro_explicit(&host_path, &dst, true)?;
                }
            }

            // Step 6: bind-mount /dev read-write so ptys / tty work in the shell.
            mount_bind_rw_explicit(Path::new("/dev"), &new_root.join("dev"), true)?;

            // Step 7: mount fresh proc, sysfs, tmpfs for /proc /sys /tmp /run.
            nix_mount(
                Some("proc"),
                &new_root.join("proc"),
                Some("proc"),
                MsFlags::empty(),
                None::<&str>,
            )?;
            nix_mount(
                Some("sysfs"),
                &new_root.join("sys"),
                Some("sysfs"),
                MsFlags::empty(),
                None::<&str>,
            )?;
            nix_mount(
                Some("tmpfs"),
                &new_root.join("tmp"),
                Some("tmpfs"),
                MsFlags::empty(),
                Some("mode=1777"),
            )?;
            nix_mount(
                Some("tmpfs"),
                &new_root.join("run"),
                Some("tmpfs"),
                MsFlags::empty(),
                Some("mode=755"),
            )?;

            // Step 8: pivot into the new root.
            info!("pivoting root into {:?}", &new_root);
            pivot_root_into(&new_root, &put_old)?;
            info!("pivot complete — now inside sandbox root");

            // Step 9: spawn shell and wait.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let rx = shell_prefs.spawn()?;
                rx.wait_for_child().await?;
                aok!()
            })?;
        }

```
