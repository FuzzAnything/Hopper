#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/fuzz_extend.rs"));

pub fn hopper_extend() {
    log::debug!("hopper extend loaded");
}
