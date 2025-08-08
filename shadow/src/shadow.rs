#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate arwah;

fuzz_target!(|data: &[u8]| {
    let _ = arwah::centrifuge::service::arwah_parse_eth(&data);
});
