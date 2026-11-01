fn main() {
    if !heterodyne_receiver_owner::protected_manual_bootstrap_entry() {
        eprintln!("HOLD: manual receiver initialization requires reconciliation; no replay");
        std::process::exit(2);
    }
}
