use std::collections::HashMap;

use crate::{execute::StatusType, EnumKind, FuzzProgram, FuzzStmt, MutateOperation};

/// Statistics of different operations,
/// mesure how many success or failure feedback it got.
#[derive(Default, Debug)]
pub struct OperationStat {
    /// statistics of all operations
    pub op_stat: HashMap<String, StatusMetrics>,
    /// statistics of inserting different funcitons
    pub call_insert: HashMap<String, StatusMetrics>,
    /// stat for deterministic operations
    pub det_stat: HashMap<String, StatusMetrics>,
    /// number of each target functions executed
    pub exec_stat: HashMap<String, StatusMetrics>,
    /// times of mutation of each seed
    pub seed_stat: HashMap<usize, StatusMetrics>,
}

/// Use execution status as metrics
#[derive(Default, Debug)]
pub struct StatusMetrics {
    pub success: usize,
    pub failure: usize,
    pub suc_new: usize,
    pub fail_new: usize,
}

impl OperationStat {
    pub fn count_ops(&mut self, program: &FuzzProgram, status: StatusType, has_new: bool) {
        // count times of mutation
        if let Some(parent) = program.parent {
            if let Some(metrics) = self.seed_stat.get_mut(&parent) {
                metrics.count(status, has_new);
            } else {
                let mut metrics = StatusMetrics::default();
                metrics.count(status, has_new);
                self.seed_stat.insert(parent, metrics);
            }
        }
        // count times of execution of each api
        for is in program.stmts.iter() {
            if let FuzzStmt::Call(call) = &is.stmt {
                self.count_exec(&call.name, status, has_new)
            }
        }
        let ops = &program.ops;
        if ops.len() == 1 {
            let first = &ops[0];
            if first.det {
                count_op(&mut self.det_stat, first.op.kind(), status, has_new);
            }
        }
        if let Some(f_name) = get_op_fname(program) {
            self.count_func(f_name, status, has_new);
        }
        if ops.is_empty() {
            let kind = "Generate";
            count_op(&mut self.op_stat, kind, status, has_new);
        }
        for op in ops {
            if let MutateOperation::BufHavoc {
                use_bytes: _,
                swap: _,
                op,
            } = &op.op
            {
                count_op(&mut self.op_stat, op.op.kind(), status, has_new);
            } else {
                count_op(&mut self.op_stat, op.op.kind(), status, has_new);
            }
        }
    }

    fn count_func(&mut self, f_name: &str, status: StatusType, has_new: bool) -> bool {
        if let Some(metrics) = self.call_insert.get_mut(f_name) {
            metrics.count(status, has_new);
            if metrics.likely_to_fail() {
                crate::log!(
                    warn,
                    "insert function `{}` is likely to cause crash later!",
                    f_name
                );
                crate::set_function_constraint_with(f_name, |fc| fc.insert_fail = true).unwrap();
                return true;
            }
        } else {
            let mut metrics = StatusMetrics::default();
            metrics.count(status, has_new);
            self.call_insert.insert(f_name.to_string(), metrics);
        }
        false
    }

    pub fn count_func_infer(&mut self, f_name: &str, program: &FuzzProgram) -> bool {
        if let Some(op_f_name) = get_op_fname(program) {
            if f_name == op_f_name {
                return false;
            }
        } 
        self.count_func(f_name, StatusType::Timeout, true);
        true
    }

    fn count_exec(&mut self, f_name: &str, status: StatusType, has_new: bool) {
        if let Some(metrics) = self.exec_stat.get_mut(f_name) {
            metrics.count(status, has_new);
        } else {
            let mut metrics = StatusMetrics::default();
            metrics.count(status, has_new);
            self.exec_stat.insert(f_name.to_string(), metrics);
        }
    }

    pub fn get_rarely_fuzz_targets(&self) -> Option<Vec<String>> {
        let mut list: Vec<(&String, &StatusMetrics)> = self.exec_stat.iter().collect();
        if list.len() < 10 {
            return None;
        }
        list.sort_by(|a, b| a.1.success.cmp(&b.1.success));
        let n = 5.max(list.len() / 10);
        let keys: Vec<String> = list[..n].iter().map(|v| v.0.to_string()).collect();
        if keys.is_empty() {
            return None;
        }
        Some(keys)
    }
}

impl StatusMetrics {
    pub fn count(&mut self, status: StatusType, has_new: bool) {
        if status.is_normal() {
            self.success += 1;
            if has_new {
                self.suc_new += 1;
            }
        } else {
            self.failure += 1;
            if has_new {
                self.fail_new += 1;
            }
        }
    }

    pub fn likely_to_fail(&self) -> bool {
        if self.failure > 10 && (self.success == 0 || self.failure / self.success > 5)
            || self.fail_new >= 3
        {
            return true;
        }
        false
    }

    pub fn log(&self) -> String {
        format!(
            "{},{},{},{}",
            self.success, self.failure, self.suc_new, self.fail_new
        )
    }
}

fn get_op_fname(program: &FuzzProgram) -> Option<&str> {
    if let Some(op) = program.ops.first() {
        match &op.op {
            MutateOperation::CallImplicitInsert {
                f_name,
                rng_state: _,
            } => {
                return Some(f_name);
            }
            MutateOperation::CallRelatedInsert {
                f_name,
                arg_pos: _,
                rng_state: _,
            } => {
                return Some(f_name);
            }
            _ => {}
        } 
    }
    None
}

fn count_op(
    map: &mut HashMap<String, StatusMetrics>,
    kind: &str,
    status: StatusType,
    has_new: bool,
) {
    if let Some(metrics) = map.get_mut(kind) {
        metrics.count(status, has_new);
    } else {
        let mut metrics = StatusMetrics::default();
        metrics.count(status, has_new);
        map.insert(kind.to_string(), metrics);
    }
}

impl Drop for OperationStat {
    fn drop(&mut self) {
        if cfg!(test) {
            return;
        }
        use std::io::Write;

        crate::log!(info, "save op stat..");
        // crate::log!(info, "{self:?}");
        let path = crate::config::output_file_path("misc/stat_op.csv");
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "op,suc,fail,suc_new,fail_new").unwrap();
        for (op, metrics) in &self.op_stat {
            writeln!(f, "{},{}", op, metrics.log()).unwrap();
        }

        let path = crate::config::output_file_path("misc/stat_det.csv");
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "op,suc,fail,suc_new,fail_new").unwrap();
        for (op, metrics) in &self.det_stat {
            writeln!(f, "{},{}", op, metrics.log()).unwrap();
        }

        let path = crate::config::output_file_path("misc/stat_call.csv");
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "call,suc,fail,suc_new,fail_new").unwrap();
        for (call, metrics) in &self.call_insert {
            writeln!(f, "{},{}", call, metrics.log()).unwrap();
        }

        let path = crate::config::output_file_path("misc/stat_exec.csv");
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "target,suc,fail,suc_new,fail_new").unwrap();
        for (target, metrics) in &self.exec_stat {
            writeln!(f, "{},{}", target, metrics.log()).unwrap();
        }

        let path = crate::config::output_file_path("misc/stat_seed.csv");
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "seed,suc,fail,suc_new,fail_new").unwrap();
        for (seed, metrics) in &self.seed_stat {
            writeln!(f, "{},{}", seed, metrics.log()).unwrap();
        }

        crate::dump_cmp_log();
    }
}

#[test]
fn test_get_rarely() {
    let mut stats = OperationStat::default();
    for i in 1..20 {
        for _ in 0..i {
            let name = format!("f_{i}");
            stats.count_exec(&name, StatusType::default(), false);
        }
    }

    let rare = stats.get_rarely_fuzz_targets();
    println!("rare: {rare:?}");
    assert!(rare.is_some());
    assert_eq!(rare.unwrap()[0], "f_1");
}
