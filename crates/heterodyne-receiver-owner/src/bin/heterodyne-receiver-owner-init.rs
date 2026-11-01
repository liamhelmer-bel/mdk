fn main() {
    if !heterodyne_receiver_owner::protected_owner_init_entry() {
        eprintln!("HOLD: protected owner initialization refused");
        std::process::exit(2);
    }
}
