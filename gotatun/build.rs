pub fn main() {
    // Enable the use of `#[cfg(profile = "release")]`-attributes.
    println!(r#"cargo:rustc-check-cfg=cfg(profile, values("release"))"#);
    if let Ok(profile) = std::env::var("PROFILE") {
        println!("cargo:rustc-cfg=profile={:?}", profile);
    }
}
