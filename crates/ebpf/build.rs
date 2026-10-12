fn main() {
    // bpf-linker's ordered memcpy expansion also disables generic memset
    // expansion. Aya's fallback then loops over a caller's stack pointer,
    // which kernels can reject without CAP_PERFMON/CAP_SYS_ADMIN. Expand our
    // fixed-size memory operations into loads/stores instead.
    println!("cargo:rustc-link-arg=--disable-expand-memcpy-in-order");
}
