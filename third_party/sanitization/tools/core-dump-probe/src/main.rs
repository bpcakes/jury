use sanitization::LockedSecretBytes;

fn marker_byte(pid: u32, index: usize) -> u8 {
    let mixed = pid
        .wrapping_mul(0x9E37_79B9)
        .rotate_left((index % 31) as u32)
        .wrapping_add((index as u32).wrapping_mul(0x45D9_F3B));
    (mixed ^ (mixed >> 8) ^ (mixed >> 16) ^ (mixed >> 24)) as u8
}

fn main() {
    let pid = std::process::id();
    let secret = LockedSecretBytes::<32>::from_fn(|index| marker_byte(pid, index))
        .expect("native locked probe allocation");
    std::hint::black_box(&secret);
    std::process::abort();
}
