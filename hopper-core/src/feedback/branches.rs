use crate::execute::StatusType;
use crate::{BucketType, BRANCHES_SIZE};

use std::io::prelude::*;
use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        RwLock,
    },
};

pub type BranchBuf = [BucketType; BRANCHES_SIZE];
const BUCKET_MASK: BucketType = BucketType::MAX;

/// Maintain global feedbacks
pub struct GlobalBranches {
    virgin_branches: RwLock<Box<BranchBuf>>,
    tmouts_branches: RwLock<Box<BranchBuf>>,
    crashes_branches: RwLock<Box<BranchBuf>>,
    num_edge: AtomicUsize,
}

impl Default for GlobalBranches {
    fn default() -> Self {
        Self {
            virgin_branches: RwLock::new(Box::new([BUCKET_MASK; BRANCHES_SIZE])),
            tmouts_branches: RwLock::new(Box::new([BUCKET_MASK; BRANCHES_SIZE])),
            crashes_branches: RwLock::new(Box::new([BUCKET_MASK; BRANCHES_SIZE])),
            num_edge: AtomicUsize::new(0),
        }
    }
}

impl GlobalBranches {
    pub fn load_from_file() -> Self {
        let path = crate::config::output_file_path("misc/branches");
        let mut f = std::fs::File::open(path).unwrap();
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        let array = unsafe {
            buffer
                .align_to::<BucketType>()
                .1
                .to_vec()
                .try_into()
                .unwrap()
        };
        Self {
            virgin_branches: RwLock::new(Box::new(array)),
            tmouts_branches: RwLock::new(Box::new([BUCKET_MASK; BRANCHES_SIZE])),
            crashes_branches: RwLock::new(Box::new([BUCKET_MASK; BRANCHES_SIZE])),
            num_edge: AtomicUsize::new(0),
        }
    }

    pub fn get_num_edge(&self) -> usize {
        self.num_edge.load(Ordering::Relaxed)
    }

    pub fn get_coverage_density(&self) -> f32 {
        (self.get_num_edge() * 10000 / BRANCHES_SIZE) as f32 / 100.0
    }

    pub fn has_new(
        &self,
        trace: &[(usize, BucketType)],
        status: StatusType,
    ) -> Vec<(usize, BucketType)> {
        let gb_map = match status {
            StatusType::Normal { .. } => &self.virgin_branches,
            StatusType::Timeout => &self.tmouts_branches,
            StatusType::Crash { .. } => &self.crashes_branches,
            _ => {
                return vec![];
            }
        };
        let mut to_update = vec![];
        {
            // read only
            let gb_map_read = gb_map.read().unwrap();
            for &br in trace {
                let gb_v = gb_map_read[br.0];
                if (br.1 & gb_v) > 0 {
                    to_update.push(br);
                }
            }
        }

        let has_new = !to_update.is_empty();
        crate::log!(
            trace,
            "has_new: {}, edge_update_num: {}",
            has_new,
            to_update.len()
        );

        to_update
    }

    pub fn has_new_uniq(
        &self,
        trace: &[(usize, BucketType)],
        status: StatusType,
    ) -> Vec<(usize, BucketType)> {
        let gb_map = match status {
            StatusType::Normal { .. } => &self.virgin_branches,
            StatusType::Timeout => &self.tmouts_branches,
            StatusType::Crash { .. } => &self.crashes_branches,
            _ => {
                return vec![];
            }
        };

        let mut to_update = vec![];
        {
            // read only
            let gb_map_read = gb_map.read().unwrap();
            for &br in trace {
                let gb_v = gb_map_read[br.0];
                if gb_v == BUCKET_MASK {
                    to_update.push(br);
                }
            }
        }

        to_update
    }

    pub fn merge_coverage(&mut self, update_list: &[(usize, BucketType)], status: StatusType) {
        let gb_map = match status {
            StatusType::Normal { .. } => &self.virgin_branches,
            StatusType::Timeout => &self.tmouts_branches,
            StatusType::Crash { .. } => &self.crashes_branches,
            _ => {
                return;
            }
        };
        let mut num_new_edge = 0;
        let mut gb_map_write = gb_map.write().unwrap();
        for &br in update_list {
            let gb_v = gb_map_write[br.0];
            if gb_map_write[br.0] == BUCKET_MASK {
                num_new_edge += 1;
            }
            gb_map_write[br.0] = gb_v & (!br.1);
        }

        if num_new_edge > 0 && status.is_normal() {
            // only count virgin branches
            self.num_edge.fetch_add(num_new_edge, Ordering::Relaxed);
        }
    }

    pub fn clean(&mut self) {
        let mut gb_map_write = self.crashes_branches.write().unwrap();
        gb_map_write.iter_mut().for_each(|m| *m = BUCKET_MASK);
        let mut gb_map_write = self.virgin_branches.write().unwrap();
        gb_map_write.iter_mut().for_each(|m| *m = BUCKET_MASK);
        let mut gb_map_write = self.tmouts_branches.write().unwrap();
        gb_map_write.iter_mut().for_each(|m| *m = BUCKET_MASK);
    }
}

impl fmt::Display for GlobalBranches {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#edge: {}, density: {:.2}%",
            self.get_num_edge(),
            self.get_coverage_density()
        )
    }
}

impl Drop for GlobalBranches {
    fn drop(&mut self) {
        if cfg!(test) {
            return;
        }
        crate::log!(info, "dump branches..");
        let path = crate::config::output_file_path("misc/branches");
        let mut f = std::fs::File::create(path).unwrap();
        let buf = self.virgin_branches.read().unwrap();
        let slice = unsafe { buf.align_to::<u8>().1 };
        f.write_all(slice).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_empty() {
        let global_branches = GlobalBranches::default();
        let trace = vec![];
        let new_edges = global_branches.has_new(&trace, StatusType::default());
        assert!(new_edges.is_empty());
        let new_edges = global_branches.has_new(&trace, StatusType::Timeout);
        assert!(new_edges.is_empty());
    }

    #[test]
    fn branch_find_new() {
        let mut global_branches = GlobalBranches::default();
        let trace = vec![(4, 1), (5, 1), (8, 3)];
        let new_edges = global_branches.has_new(&trace, StatusType::default());
        assert_eq!(new_edges.len(), 3);
        global_branches.merge_coverage(&new_edges, StatusType::default());
        let new_edges = global_branches.has_new(&trace, StatusType::default());
        assert!(new_edges.is_empty());
    }
}
