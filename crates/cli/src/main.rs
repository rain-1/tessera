//! `tessera` binary. See the library docs for behaviour and exit codes.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let code = tessera_cli::main_with(
        &args,
        &mut tessera_cli::Io {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    std::process::exit(code);
}
