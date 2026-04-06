fn main() {
    // Rebuild if the partition table changes (cmake re-configure needed).
    let partitions = concat!(env!("CARGO_MANIFEST_DIR"), "/partitions.csv");
    println!("cargo:rerun-if-changed={partitions}");

    embuild::espidf::sysenv::output();
}
