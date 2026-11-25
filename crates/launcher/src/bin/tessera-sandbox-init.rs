//! In-sandbox init shim; see `tessera_launcher::init`.
#![forbid(unsafe_code)]

fn main() {
    std::process::exit(tessera_launcher::init::main_with_args(
        std::env::args_os().skip(1),
    ));
}
