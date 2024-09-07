//! Corpus for types, lists of special values.
//! Copy from lain
use super::ObjCorpus;

static DANGEROUS_NUMBERS_U8: &[u8] = &[
    1,
    0x10,
    0x40,
    u8::MIN,             // 0x00
    u8::MAX,             // 0xff
    i8::MAX as u8,       // 0x7f
    i8::MIN as u8,       // 0x80
];

static DANGEROUS_NUMBERS_U16: &[u16] = &[
    1,
    0x40,
    0x0400,
    u8::MAX as u16,       // 0xff
    i8::MAX as u16,       // 0x7f
    // big-endian variants
    u16::MIN,              // 0x0000
    u16::MAX,              // 0xffff
    i16::MAX as u16,       // 0x7fff
    i16::MIN as u16,       // 0x8000
    // little-endian variants
    (i16::MAX as u16).swap_bytes(), // 0xff7f
    (i16::MIN as u16).swap_bytes(), // 0x0080
];

static DANGEROUS_NUMBERS_U32: &[u32] = &[
    1,
    0x40,
    0x0400,
    u8::MAX as u32,        // 0xff
    i8::MAX as u32,        // 0x7f
    u16::MAX as u32,       // 0xffff
    i16::MAX as u32,       // 0x7fff
    i16::MIN as u32,       // 0x8000
    // big-endian variants
    u32::MIN,          // 0x0000_0000
    u32::MAX,          // 0xffff_ffff
    i32::MAX as u32,   // 0x7fff_ffff
    i32::MIN as u32,   // 0x8000_0000
    // little-endian variants
    (i32::MAX as u32).swap_bytes(), // 0xffff_ff7f
    (i32::MIN as u32).swap_bytes(), // 0x0000_0080
];

static DANGEROUS_NUMBERS_U64: &[u64] = &[
    1,
    0x40,
    0x0400,
    u8::MAX as u64,        // 0xff
    i8::MAX as u64,        // 0x7f
    u16::MAX as u64,       // 0xffff
    i16::MAX as u64,       // 0x7fff
    i16::MIN as u64,       // 0x8000
    u32::MAX as u64,       // 0xffff_ffff
    i32::MAX as u64,       // 0x7fff_ffff
    i32::MIN as u64,       // 0x8000_0000
    // big-endian variants
    u64::MIN,
    u64::MAX,
    i64::MAX as u64,
    i64::MIN as u64,
    // little-endian variants
    (i64::MAX as u64).swap_bytes(), // 0xffff_ffff_ffff_ff7f
    (i64::MIN as u64).swap_bytes(), // 0x0000_0000_0000_0080
];

static DANGEROUS_NUMBERS_USIZE: &[usize] = &[
    1,
    0x40,
    0x0400,
    u8::MAX as usize,        // 0xff
    i8::MAX as usize,        // 0x7f
    u16::MAX as usize,       // 0xffff
    i16::MAX as usize,       // 0x7fff
    i16::MIN as usize,       // 0x8000
    #[cfg(target_pointer_width = "64")]
    0x7fff_ffff,
    #[cfg(target_pointer_width = "64")]
    0x8000_0000,
    #[cfg(target_pointer_width = "64")]
    0xffff_ffff,
    // big-endian variants
    usize::MIN,
    usize::MAX,
    isize::MAX as usize,
    isize::MIN as usize,
    // little-endian variants
    (isize::MAX as usize).swap_bytes(),
    (isize::MIN as usize).swap_bytes(),
];

static DANGEROUS_NUMBERS_F32: &[f32] = &[
    f32::INFINITY,
    f32::MAX,
    f32::MIN,
    f32::MIN_POSITIVE,
    f32::NAN,
    f32::NEG_INFINITY,
];

static DANGEROUS_NUMBERS_F64: &[f64] = &[
    f64::INFINITY,
    f64::MAX,
    f64::MIN,
    f64::MIN_POSITIVE,
    f64::NAN,
    f64::NEG_INFINITY,
];

macro_rules! impl_corpus {
    ( $ty:ident, $corpus:ident ) => {
        impl ObjCorpus for $ty {
            fn corpus_size() -> usize {
                $corpus.len()
            }

            fn get_interesting_value(index: usize) -> Option<Self> {
                Some($corpus[index] as $ty)
            }
        }
    };
}

impl_corpus!(u8, DANGEROUS_NUMBERS_U8);
impl_corpus!(i8, DANGEROUS_NUMBERS_U8);
impl_corpus!(u16, DANGEROUS_NUMBERS_U16);
impl_corpus!(i16, DANGEROUS_NUMBERS_U16);
impl_corpus!(u32, DANGEROUS_NUMBERS_U32);
impl_corpus!(i32, DANGEROUS_NUMBERS_U32);
impl_corpus!(u64, DANGEROUS_NUMBERS_U64);
impl_corpus!(i64, DANGEROUS_NUMBERS_U64);
impl_corpus!(f32, DANGEROUS_NUMBERS_F32);
impl_corpus!(f64, DANGEROUS_NUMBERS_F64);
impl_corpus!(u128, DANGEROUS_NUMBERS_U64);
impl_corpus!(i128, DANGEROUS_NUMBERS_U64);
impl_corpus!(usize, DANGEROUS_NUMBERS_USIZE);
impl_corpus!(isize, DANGEROUS_NUMBERS_USIZE);

