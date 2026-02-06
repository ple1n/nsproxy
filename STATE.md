# NSProxy State Organization

## Directories

### `/run/nsproxy/` - Runtime (ephemeral)
- `*.ns` - Namespace bind mount files
- `*.json` - Metadata for each namespace (NsAlive struct)
- `priv_mnt/{userns_id}.user/*.ns` - User namespace specific mounts

### `/nsp3/{instance-name}` - Persistent profiles

## Usage

```bash
# Create profile
nsproxy profile myapp

# Run with profile (auto-derives /nsp3/myapp/profile.json)
nsproxy make --name myapp --bind /run/nsproxy/myapp.ns

# Enter namespace
nsproxy enter /run/nsproxy/myapp.ns
nsproxy enter --name myapp
```

## Path Helpers (lib.rs)

```rust
use nsproxy_core::state_paths;

state_paths::profile_config("myapp")    // /nsp3/myapp/profile.json
state_paths::hot_config("myapp")        // /nsp3/myapp/hot.json
state_paths::ns_bind_mount("myapp")     // /run/nsproxy/myapp.ns
state_paths::ns_metadata("myapp")       // /run/nsproxy/myapp.json
state_paths::metadata_for_bind(&path)   // {path}.json
```

## Key Structs

**NsAlive** (`/run/nsproxy/*.json`):
```rust
{
  browser_profile: Option<String>,  // For env restoration
  bind_mount: PathBuf,              // Path to .ns file
  child_pid: Option<u32>            // Container process
}
```

**ProfileConfig** (`/nsp3/*/profile.json`):
```rust
{
  schema: u32,
  rootfs: ProfileRootfs,            // Overlay vs Pivot
  mounts: Vec<ProfileMount>,
  env: HashMap<String, String>,
  hot: PathBuf,                     // Path to hot.json
  sargs: ShellArgs                  // uid, gid, shell, cwd
}
```

**HotConfig** (`/nsp3/*/hot.json`):
```rust
{
  dns: HashMap<String, String>,     // Virtual DNS
  devs: HashMap<String, String>,    // Network devices
  mnt: HashMap<PathBuf, PathBuf>,   // Bind mounts
  locals: HashMap<u32, u32>         // Port forwarding
}
```
