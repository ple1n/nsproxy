use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

fn main() {
    let web_root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("web");
    let dist = web_root.join("dist");
    println!("cargo:rerun-if-env-changed=NSPROXY_WEBUI");
    println!("cargo:rerun-if-changed={}", web_root.display());
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut assets = Vec::new();
    let web_ui_requested = std::env::var("NSPROXY_WEBUI").as_deref() == Ok("1");
    let web_ui_bundled = web_ui_requested && dist.join("index.html").is_file();
    if web_ui_bundled {
        collect_assets(&dist, &dist, &mut assets);
    } else {
        if web_ui_requested {
            println!("cargo:warning=React UI bundle missing; serving build instructions instead");
        }
        assets.push(("index.html".to_owned(), web_root.join("fallback.html")));
    }
    assets.sort_by(|left, right| left.0.cmp(&right.0));

    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("web_assets.rs");
    let mut file = fs::File::create(out).expect("create generated web assets");
    writeln!(
        file,
        "pub(crate) const WEB_UI_BUNDLED: bool = {web_ui_bundled};"
    )
    .expect("write web UI availability");
    writeln!(file, "pub(crate) static WEB_ASSETS: &[(&str, &[u8])] = &[")
        .expect("write generated asset table");
    for (name, path) in assets {
        println!("cargo:rerun-if-changed={}", path.display());
        writeln!(
            file,
            "    ({name:?}, include_bytes!({path:?}).as_slice()),",
            path = path.to_string_lossy()
        )
        .expect("write generated asset entry");
    }
    writeln!(file, "];").expect("finish generated asset table");
}

fn collect_assets(root: &Path, directory: &Path, assets: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(directory).expect("read React UI bundle") {
        let entry = entry.expect("read React UI bundle entry");
        let path = entry.path();
        if path.is_dir() {
            collect_assets(root, &path, assets);
        } else if path.is_file() {
            let name = path
                .strip_prefix(root)
                .expect("asset path is inside bundle")
                .to_string_lossy()
                .replace('\\', "/");
            assets.push((name, path));
        }
    }
}
