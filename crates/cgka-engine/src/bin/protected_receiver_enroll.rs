//! Fixed fresh-enrollment entry; no caller argv or approval DTO.
fn main() {
    #[cfg(target_os = "linux")]
    let success = cgka_engine::protected_receiver_enroll_main();
    #[cfg(not(target_os = "linux"))]
    let success = false;
    if !success {
        eprintln!("protected receiver enrollment HOLD");
        std::process::exit(2);
    }
}
