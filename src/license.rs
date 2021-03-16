pub fn print_license() {
    let license = include_str!("../LICENSE");
    println!("{}", license);
}
