extern crate cc;

#[cfg(target_family = "unix")]
static ASM_FILE: &str = "asm.S";
#[cfg(target_os = "windows")]
static ASM_FILE: &str = "asm-win.S";

fn main() {
    cc::Build::new().file(ASM_FILE).compile("asm");
}
