use rand::{
    distributions::uniform::{SampleRange, SampleUniform},
    prelude::*,
};
use std::cell::RefCell;

use super::pcg::Pcg32;

pub type RngState = Pcg32;

thread_local! {
    pub static RNG: RefCell<RngState> = RefCell::new(Pcg32::seed_from_u64(rand::random()));
}

#[inline]
pub fn save_rng_state() -> RngState {
    RNG.with(|cell| cell.borrow().clone())
}

#[inline]
pub fn restore_rng_state(rng: RngState) {
    RNG.with(|cell| cell.replace(rng));
}

#[inline]
pub fn renew_rng_state() {
    RNG.with(|cell| cell.replace(Pcg32::seed_from_u64(rand::random())));
}

pub fn gen_rng_state() -> RngState {
    Pcg32::seed_from_u64(rand::random())
}

#[inline]
pub fn gen_range<T, R>(range: R) -> T
where
    T: SampleUniform,
    R: SampleRange<T>,
{
    RNG.with(|cell| cell.borrow_mut().gen_range(range))
}

#[inline]
pub fn prob(p: f64) -> bool {
    RNG.with(|cell| cell.borrow_mut().gen_bool(p))
}

#[inline]
pub fn mostly() -> bool {
    prob(0.90)
}

#[inline]
pub fn likely() -> bool {
    prob(0.65)
}

#[inline]
pub fn coin() -> bool {
    prob(0.50)
}

#[inline]
pub fn unlikely() -> bool {
    prob(0.35)
}

#[inline]
pub fn rarely() -> bool {
    prob(0.10)
}

#[inline]
pub fn gen<T>() -> T
where
    rand::distributions::Standard: Distribution<T>,
{
    RNG.with(|cell| cell.borrow_mut().gen())
}

pub fn choose_slice<T>(list: &[T]) -> Option<&T> {
    RNG.with(|cell| list.choose(&mut *cell.borrow_mut()))
}

pub fn choose_iter<T: IteratorRandom>(list: T) -> Option<T::Item> {
    RNG.with(|cell| list.choose(&mut *cell.borrow_mut()))
}

pub fn choose_multiple<T: IteratorRandom>(list: T, amount: usize) -> Vec<T::Item> {
    RNG.with(|cell| list.choose_multiple(&mut *cell.borrow_mut(), amount))
}

pub fn shuffle<T>(list: &mut [T]) {
    RNG.with(|cell| list.shuffle(&mut *cell.borrow_mut()))
}

pub fn cond_likely(cond: bool) -> bool {
    if cond {
        likely()
    } else {
        coin()
    }
}
pub struct TempRngGuard {
    cur: RngState,
}

impl TempRngGuard {
    pub fn temp_use(rng: &RngState) -> Self {
        RNG.with(|cell| {
            let cur = cell.borrow().clone();
            cell.replace(rng.clone());
            Self { cur }
        })
    }
}

impl Drop for TempRngGuard {
    fn drop(&mut self) {
        restore_rng_state(self.cur.clone());
    }
}

#[test]
fn test_tmp_rng_guard() {
    let rng_cur = save_rng_state();
    let new_rng = gen_rng_state();
    {
        let _tmp_rng = TempRngGuard::temp_use(&new_rng);
        assert_eq!(new_rng, save_rng_state());
    }
    assert_eq!(rng_cur, save_rng_state());
}
