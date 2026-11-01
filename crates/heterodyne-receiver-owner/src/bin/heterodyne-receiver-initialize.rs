fn main() {
    if !heterodyne_receiver_owner::protected_initializer_entry() {
        eprintln!("protected initialization HOLD; preserve original generation");
        std::process::exit(2);
    }
}
