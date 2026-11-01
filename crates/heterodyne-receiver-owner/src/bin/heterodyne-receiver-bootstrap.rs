fn main() {
    if !heterodyne_receiver_owner::protected_bootstrap_entry() {
        eprintln!("HOLD: receiver bootstrap requires reconciliation; automatic replay forbidden");
        std::process::exit(2);
    }
}
