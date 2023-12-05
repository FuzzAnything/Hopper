extern crate cc;

fn main() {
    if cfg!(feature = "e9_mode") {
        #[cfg(target_family = "unix")]
        cc::Build::new().file("src/feedback/globl/e9-globl.S").compile("e9");
        #[cfg(target_family = "windows")]
        cc::Build::new().file("src/feedback/globl/e9-globl-win.S").compile("e9");
    } else if cfg!(feature = "llvm_mode") {
        cc::Build::new()
            .file("src/feedback/globl/llvm-globl.c")
            .compile("llvm-globl");
    }
    cc::Build::new()
    .file("src/feedback/globl/variadic.c")
    .define("_LARGEFILE64_SOURCE", "1")
    .compile("variadic");
}
