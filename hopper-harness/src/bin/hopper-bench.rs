//! Used for benchmark hopper's runtime efficient
//! Since we do not set core_limit, you should set:
//! ulimit -c 0

use std::{path::PathBuf, io::Read};

pub fn main() {
    hopper_harness::hopper_extend();
    if let Some(dir) = std::env::args().nth(1) {
        let mut executor = hopper::Executor::default();
        hopper::init_depot_dirs().unwrap();
        // let mut feedback = hopper::Feedback::new().unwrap();
        // feedback.clear();
        // executor.set_timeout(1);
        let start_at = std::time::Instant::now();
        let path = PathBuf::from(dir);
        let mut inputs = vec![];
        for entry in path.read_dir().unwrap() {
            let file = entry.unwrap().path();
            if !file.is_file() {
                continue;
            }
            let mut buffer = String::new();
            let mut f = std::fs::File::open(file).unwrap();
            f.read_to_string(&mut buffer).unwrap();
            inputs.push(buffer);
        }
        let start_run_at = std::time::Instant::now();

        for (i, input) in inputs.iter().enumerate() {
            let ret = executor.execute(|| {
                let mut program = hopper::read_program(input, false).unwrap();
                program.eval()
            });
            println!("{i}, {ret:?}");
        }

        let t_run = start_run_at.elapsed();
        let t_all = start_at.elapsed();
        println!("num: {}, run: {}s, all: {}s", inputs.len(), t_run.as_secs_f32(), t_all.as_secs_f32());

    }
}
