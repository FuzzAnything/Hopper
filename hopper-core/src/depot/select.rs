use std::cell::Cell;

use crate::{FuzzProgram, SelectType, FeedbackSummary};

use super::Depot;



/// Select seed input form depot
pub trait Selector {
    fn init_score(&self, program: &FuzzProgram, feedback: &FeedbackSummary) -> (u64, f64);
    fn next_score(&self, score: (u64, f64)) -> (u64, f64);
}

/// Round Robin
pub struct RrSelector;

/// Simulated annealing
pub struct SaSelector;

const RR_BASE: u64 = 100000;
const RR_STEP: u64 = 1;

impl Selector for RrSelector {
    fn init_score(&self, program: &FuzzProgram, _feedback: &FeedbackSummary) -> (u64, f64) {
        let bonus = get_bonus(program);
        (RR_BASE + bonus, 0_f64)
    }

    fn next_score(&self, score: (u64, f64)) -> (u64, f64) {
        if score.0 == 0 {
            return score;
        }
        (score.0 - RR_STEP, score.1)
    }
}

// base score
const SA_BASE: f64 = 60_f64;
// 20**(-N/500)
const SA_COE: f64 = 0.9_f64;
// for fresh seeds
const SA_UNIQ_NEW: u64 = 3;
// bonus for key function
const KEY_BONUS: u64 = 2;

thread_local! {
    static AVG_SCORE: Cell<(f64, u64)> = const { Cell::new((0_f64, 0_u64)) };
}

impl Selector for SaSelector {
    fn init_score(&self, program: &FuzzProgram, feedback: &FeedbackSummary) -> (u64, f64) {
        let edge_num = feedback.path_len as u128;
        let t_used = feedback.time_used as f64;
        let call_num = program.stmts.iter().filter(|s| s.stmt.is_call()).count() as u128;
        assert!(call_num > 0, "The number of call statements cannot be zero!");
        let r = (edge_num / call_num) as f64 / t_used;
        // make the range of `r` to be [0, 5];
        let avg = AVG_SCORE.with(|c| {
            let (mut avg, mut num) = c.get();
            let sum = avg.mul_add(num as f64, r);
            num += 1;
            avg = sum / (num as f64);
            c.replace((avg, num));
            avg
        });
        let mut coef = r / avg;
        if coef > 5_f64 {
            coef = 5_f64;
        }
        let score = SA_BASE * (1_f64 + coef);
        let mut bonus = get_bonus(program);
        crate::log!(
            debug,
            "#edge: {edge_num}, #t: {t_used}, #call: {call_num}, score: {score}"
        );
        if feedback.has_new_uniq_path {
            bonus += SA_UNIQ_NEW;
        }
        (bonus, score)
    }

    fn next_score(&self, score: (u64, f64)) -> (u64, f64) {
        if score.0 > 0 {
            (score.0 - 1, score.1)
        } else {
            (0, score.1 * SA_COE)
        }
    }
}

impl Depot {
    pub fn select_seed(&mut self) -> Option<FuzzProgram> {
        if let Some(mut entry) = self.queue.peek_mut() {
            crate::log!(debug, "select program {} as seed, score: {:?}", entry.data.id, entry.score);
            entry.score = self.selector.next_score(entry.score);
            return Some(entry.data.clone());
        }
        None
    }
}

pub fn init_selector(ty: &SelectType) -> Box<dyn Selector> {
    match ty {
        SelectType::Rr => Box::new(RrSelector),
        SelectType::Sa => Box::new(SaSelector),
    }
}

/// Bonus for specific programs
fn get_bonus(program: &FuzzProgram) -> u64 {
    if let Some(call) = program.get_target_stmt() {
        // bonus for key function
        if crate::config::get_config().func_key.contains(&call.name) {
            return KEY_BONUS;
        }
    }
    0
}

#[test]
fn test_priority_in_queue() {
    use super::PriorityWrap;
    use std::collections::BinaryHeap;
    let selector = RrSelector;
    let mut heap = BinaryHeap::new();
    heap.push(PriorityWrap::new(1, (200, 100_f64)));
    heap.push(PriorityWrap::new(2, (200, 100_f64)));
    for _ in 0..10 {
        let v1 = {
            let mut entry = heap.peek_mut().unwrap();
            println!("v1: {}", *entry);
            entry.score = selector.next_score(entry.score);
            entry.data
        };
        let v2 = {
            let mut entry = heap.peek_mut().unwrap();
            println!("v2: {}", *entry);
            entry.score = selector.next_score(entry.score);
            entry.data
        };
        assert_ne!(v1, v2);
    }
}
