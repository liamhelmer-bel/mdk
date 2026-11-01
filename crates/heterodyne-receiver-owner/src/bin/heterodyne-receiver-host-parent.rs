fn main() {
    if !heterodyne_receiver_owner::protected_host_parent_entry() {
        eprintln!("HOLD: host deployment requires reconciliation; automatic replay forbidden");
        std::process::exit(2);
    }
}
