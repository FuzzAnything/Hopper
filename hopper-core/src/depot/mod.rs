mod io;
mod priority;
mod select;

use std::{collections::BinaryHeap, fmt};

use self::select::*;
use crate::{execute::StatusType, FuzzProgram, FeedbackSummary};
pub use io::*;
use priority::PriorityWrap;
pub use priority::*;

/// Depot for saving all inputs, hangs, and crashes.
pub struct Depot {
    pub queue: BinaryHeap<PriorityWrap<FuzzProgram>>,
    pub inputs: DepotDir,
    pub hangs: DepotDir,
    pub crashes: DepotDir,
    pub selector: Box<dyn Selector>,
}

impl Depot {
    /// Create new depot.
    pub fn new() -> eyre::Result<Self> {
        let (inputs, hangs, crashes) = io::init_depot_dirs()?;
        Ok(Self {
            queue: BinaryHeap::new(),
            inputs,
            hangs,
            crashes,
            selector: init_selector(&crate::config::get_config().select),
        })
    }

    /// Fetch new ID
    pub fn fetch_id(&mut self, status: StatusType) -> usize {
        match status {
            StatusType::Normal { .. } => self.inputs.inc_id(),
            StatusType::Timeout => self.hangs.inc_id(),
            StatusType::Crash { .. } => self.crashes.inc_id(),
            _ => 0,
        }
    }
    
    /// Save new interesting input into depot.
    pub fn save(
        &mut self,
        status: StatusType,
        program: &FuzzProgram,
        sync: bool,
    ) -> eyre::Result<()> {
        if sync {
            return Ok(());
        }
        match status {
            StatusType::Normal { .. } => self.inputs.save_program(program, status),
            StatusType::Timeout => self.hangs.save_program(program, status),
            StatusType::Crash { .. } => self.crashes.save_program(program, status),
            _ => {
                eyre::bail!("unknown status type");
            }
        }
    }

    pub fn add_appendix(
        &mut self,
        status: StatusType,
        id: usize,
        appendix: &str,
    ) -> eyre::Result<()> {
        match status {
            StatusType::Normal { .. } => self.inputs.add_appendix(id, appendix),
            StatusType::Timeout => self.hangs.add_appendix(id, appendix),
            StatusType::Crash { .. } => self.crashes.add_appendix(id, appendix),
            _ => {
                eyre::bail!("unknown status type");
            }
        }
    }

    /// put program in the queue,
    pub fn push_queue(&mut self, program: FuzzProgram, feedback: &FeedbackSummary) -> eyre::Result<()> {
        let id = program.id;
        let score = self.selector.init_score(&program, feedback);
        self.queue.push(PriorityWrap::new(program, score));
        crate::log!(
            debug,
            "put new program on queue, id: {id}, priority score: {score:?}"
        );
        if self.queue.len() > crate::config::MAX_QUEUE_SIZE {
            // To make the memory usage to be low,
            // we find the seeds with small IDs, and kick out them
            let archived = id - self.queue.len() + 5;
            self.queue.retain(|item| item.data.id > archived);
        }
        Ok(())
    }

    /// Get program in queue by id
    pub fn get_program_by_id(&self, id: usize) -> Option<&FuzzProgram> {
        self.queue
            .iter()
            .find(|p| p.data.id == id)
            .map(|qw| &qw.data)
    }
}

impl fmt::Display for Depot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#queue: {}, #crashes: {}, #hangs: {}",
            self.inputs.size(),
            self.crashes.size(),
            self.hangs.size(),
        )
    }
}
