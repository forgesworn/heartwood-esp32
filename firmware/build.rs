use std::path::PathBuf;

fn main() {
    // Copy partitions.csv into esp-idf-sys's generated CMake project directory.
    //
    // Context: `CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"` in
    // sdkconfig.defaults is resolved by esp-idf's CMake layer relative to
    // the generated project directory, which for esp-idf-sys lives at
    // target/<target>/<profile>/build/esp-idf-sys-<hash>/out/. The hash
    // changes across rebuilds when esp-idf-sys features change, so we
    // can not hard-code it. Instead, we find any esp-idf-sys-* directory
    // under the target build dir and copy our project-root partitions.csv
    // into its out/ subdirectory. If no directory exists yet (fresh build),
    // we skip quietly -- esp-idf-sys's own build.rs will create the dir and
    // the next cargo invocation will populate it. First cargo build after
    // `cargo clean` therefore needs a second run; acceptable one-off cost.
    let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let partitions_src = project_dir.join("partitions.csv");
    println!("cargo:rerun-if-changed={}", partitions_src.display());

    if let Ok(target_triple) = std::env::var("TARGET") {
        let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
        let build_root = project_dir
            .join("target")
            .join(&target_triple)
            .join(&profile)
            .join("build");
        if build_root.exists() {
            if let Ok(entries) = std::fs::read_dir(&build_root) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("esp-idf-sys-") {
                        let out_dir = entry.path().join("out");
                        if out_dir.exists() {
                            let dst = out_dir.join("partitions.csv");
                            if let Err(e) = std::fs::copy(&partitions_src, &dst) {
                                println!("cargo:warning=failed to copy partitions.csv to {}: {}",
                                    dst.display(), e);
                            } else {
                                println!("cargo:warning=copied partitions.csv into {}",
                                    dst.display());
                            }
                        }
                    }
                }
            }
        }
    }

    embuild::espidf::sysenv::output();
}
