//! Corpus for types, lists of special values.
//! Copy from lain
use super::ObjCorpus;

static DANGEROUS_NUMBERS_U8: &[u8] = &[
    1,
    0x10,
    0x40,
    std::u8::MIN,             // 0x00
    std::u8::MAX,             // 0xff
    std::i8::MAX as u8,       // 0x7f
    std::i8::MIN as u8,       // 0x80
];

static DANGEROUS_NUMBERS_U16: &[u16] = &[
    1,
    0x40,
    0x0400,
    std::u8::MAX as u16,       // 0xff
    std::i8::MAX as u16,       // 0x7f
    // big-endian variants
    std::u16::MIN,              // 0x0000
    std::u16::MAX,              // 0xffff
    std::i16::MAX as u16,       // 0x7fff
    std::i16::MIN as u16,       // 0x8000
    // little-endian variants
    (std::i16::MAX as u16).swap_bytes(), // 0xff7f
    (std::i16::MIN as u16).swap_bytes(), // 0x0080
];

static DANGEROUS_NUMBERS_U32: &[u32] = &[
    1,
    0x40,
    0x0400,
    std::u8::MAX as u32,        // 0xff
    std::i8::MAX as u32,        // 0x7f
    std::u16::MAX as u32,       // 0xffff
    std::i16::MAX as u32,       // 0x7fff
    std::i16::MIN as u32,       // 0x8000
    // big-endian variants
    std::u32::MIN,          // 0x0000_0000
    std::u32::MAX,          // 0xffff_ffff
    std::i32::MAX as u32,   // 0x7fff_ffff
    std::i32::MIN as u32,   // 0x8000_0000
    // little-endian variants
    (std::i32::MAX as u32).swap_bytes(), // 0xffff_ff7f
    (std::i32::MIN as u32).swap_bytes(), // 0x0000_0080
];

static DANGEROUS_NUMBERS_U64: &[u64] = &[
    1,
    0x40,
    0x0400,
    std::u8::MAX as u64,        // 0xff
    std::i8::MAX as u64,        // 0x7f
    std::u16::MAX as u64,       // 0xffff
    std::i16::MAX as u64,       // 0x7fff
    std::i16::MIN as u64,       // 0x8000
    std::u32::MAX as u64,       // 0xffff_ffff
    std::i32::MAX as u64,       // 0x7fff_ffff
    std::i32::MIN as u64,       // 0x8000_0000
    // big-endian variants
    std::u64::MIN,
    std::u64::MAX,
    std::i64::MAX as u64,
    std::i64::MIN as u64,
    // little-endian variants
    (std::i64::MAX as u64).swap_bytes(), // 0xffff_ffff_ffff_ff7f
    (std::i64::MIN as u64).swap_bytes(), // 0x0000_0000_0000_0080
];

static DANGEROUS_NUMBERS_USIZE: &[usize] = &[
    1,
    0x40,
    0x0400,
    std::u8::MAX as usize,        // 0xff
    std::i8::MAX as usize,        // 0x7f
    std::u16::MAX as usize,       // 0xffff
    std::i16::MAX as usize,       // 0x7fff
    std::i16::MIN as usize,       // 0x8000
    #[cfg(target_pointer_width = "64")]
    0x7fff_ffff,
    #[cfg(target_pointer_width = "64")]
    0x8000_0000,
    #[cfg(target_pointer_width = "64")]
    0xffff_ffff,
    // big-endian variants
    std::usize::MIN,
    std::usize::MAX,
    std::isize::MAX as usize,
    std::isize::MIN as usize,
    // little-endian variants
    (std::isize::MAX as usize).swap_bytes(),
    (std::isize::MIN as usize).swap_bytes(),
];

static DANGEROUS_NUMBERS_F32: &[f32] = &[
    std::f32::INFINITY,
    std::f32::MAX,
    std::f32::MIN,
    std::f32::MIN_POSITIVE,
    std::f32::NAN,
    std::f32::NEG_INFINITY,
];

static DANGEROUS_NUMBERS_F64: &[f64] = &[
    std::f64::INFINITY,
    std::f64::MAX,
    std::f64::MIN,
    std::f64::MIN_POSITIVE,
    std::f64::NAN,
    std::f64::NEG_INFINITY,
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

