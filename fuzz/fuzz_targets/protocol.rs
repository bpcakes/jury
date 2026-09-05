#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    jury_fuzz::protocol::exercise(data);
});
