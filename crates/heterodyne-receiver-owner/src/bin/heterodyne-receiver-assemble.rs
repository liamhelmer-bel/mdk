fn main() {
    if !heterodyne_receiver_owner::protected_assembly_entry() {
        eprintln!("receiver assembly HOLD");
        std::process::exit(1);
    }
}
