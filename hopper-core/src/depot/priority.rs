use std::{
    cmp::Ordering,
    fmt::{self, Display},
};

#[derive(Debug)]
pub struct PriorityWrap<T> {
    pub data: T,
    pub score: (u64, f64),
}

impl<T> PriorityWrap<T> {
    pub fn new(data: T, score: (u64, f64)) -> Self {
        Self { data, score }
    }
}

impl<T> PartialEq for PriorityWrap<T> {
    fn eq(&self, other: &PriorityWrap<T>) -> bool {
        self.score.0 == other.score.0 && self.score.1 == other.score.1
    }
}

impl<T> Eq for PriorityWrap<T> {}

// Make the queue get largestscore first.
impl<T> Ord for PriorityWrap<T> {
    fn cmp(&self, other: &PriorityWrap<T>) -> Ordering {
        // score.0 is more important than score.1
        // only if score.0 is useless, then we use score.1
        if self.score.0 == 0 && other.score.0 == 0 {
            // use score.1
            match self.score.1.partial_cmp(&other.score.1) {
                Some(o) => match o {
                    Ordering::Greater => Ordering::Greater,
                    Ordering::Less => Ordering::Less,
                    Ordering::Equal => Ordering::Equal,
                },
                None => {
                    panic!("The priority cannot be NaN!");
                }
            }
        } else {
            match self.score.0.partial_cmp(&other.score.0) {
                Some(o) => match o {
                    Ordering::Greater => Ordering::Greater,
                    Ordering::Less => Ordering::Less,
                    Ordering::Equal =>  Ordering::Equal
                },
                None => {
                    panic!("The priority cannot be NaN!");
                }
            }
        }
    }
}

impl<T> PartialOrd for PriorityWrap<T> {
    fn partial_cmp(&self, other: &PriorityWrap<T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Display> fmt::Display for PriorityWrap<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "data: {}, priority: ({}, {})",
            self.data, self.score.0, self.score.1
        )
    }
}
