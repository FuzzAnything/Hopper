//! Observer, used to check feedback collected from program
//! inlucing branch coverage, compare instructions/functions

use eyre::Context;

use crate::{execute::StatusType, BucketType, FuzzProgram, TimeUsage};

use super::*;

pub struct Observer {
    // Feedback for current execution
    pub feedback: Feedback,
    // All branches our testcases visited
    pub branches_state: GlobalBranches,
    // Stat for operation
    pub op_stat: OperationStat,
    // Time usage
    pub usage: TimeUsage,
}

impl Observer {
    pub fn new() -> eyre::Result<Self> {
        Ok(Self {
            feedback: Feedback::new()?,
            branches_state: GlobalBranches::default(),
            op_stat: OperationStat::default(),
            usage: TimeUsage::default(),
        })
    }

    /// Check if current execution has trigger new feedback or not?
    pub fn has_new_path(&mut self, status: StatusType) -> eyre::Result<Vec<(usize, BucketType)>> {
        let _counter = self.usage.count();
        let trace = self.feedback.path.get_list();
        // crate::log!(trace, "find cov: {trace:?}");
        let ret = self.branches_state.has_new(&trace, status);
        Ok(ret)
    }

    /// Check if current execution has trigger new unique path or not?
    pub fn get_new_uniq_path(&mut self, status: StatusType) -> Vec<(usize, BucketType)> {
        let _counter = self.usage.count();
        let trace = self.feedback.path.get_list();
        self.branches_state.has_new_uniq(&trace, status)
    }


    /// Merge the update list to global coverage
    pub fn merge_coverage(&mut self, update_list: &[(usize, BucketType)], status: StatusType) {
        let _counter = self.usage.count();
        self.branches_state.merge_coverage(update_list, status);
        crate::log!(trace, "merge cov: {:?}", update_list);
    }

    /// Update cmp state and infer relationship between mutation operator and cmps
    pub fn infer_cmp(&mut self, program: &FuzzProgram) -> eyre::Result<()> {
        let _counter = self.usage.count();
        self.feedback
            .instrs
            .associate_loc_with_cmp_instructions(program)
            .with_context(|| {
                format!(
                    "fail to asscociate cmp, program:\n {}",
                    program.serialize_all().unwrap()
                )
            })
    }

    /// Check if the program using `val` as fd
    pub fn contain_fd(&self, val: i32) -> (bool, bool) {
        let fd_list = self.feedback.instrs.get_fd_list();
        let mut is_fd = false;
        let mut is_fd_read = false;
        for (fd, read) in fd_list {
            if fd == val {
                is_fd = true;
                if read {
                    is_fd_read = true;
                }
            }
        }
        (is_fd, is_fd_read)
    }

    pub fn summary_feedback(&self, status: StatusType) -> FeedbackSummary {
        let mut sf = FeedbackSummary::default();
        self.update_summary(&mut sf, status);
        sf
    }

    pub fn update_summary(&self, feedback: &mut FeedbackSummary, status: StatusType) {
        let path = self.feedback.path.get_list();
        feedback.path_len = path.len();
        feedback.num_uniq_path =  self.branches_state.has_new_uniq(&path, status).len();
    }
}
