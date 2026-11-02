fn main() {
    if !heterodyne_receiver_owner::protected_serving_bootstrap_entry() {
        eprintln!("HOLD: serving receiver requires reconciliation; no replay");
        std::process::exit(2);
    }
}
