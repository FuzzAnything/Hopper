//! Mutating module
//! Code for how to generate or mutating a program

pub mod constraints;
mod det;
pub mod effective;
mod flag;
mod generate;
mod infer;
mod minimize;
mod mutate;
mod object;
mod operator;
mod pcg;
pub mod refine;
mod rng;
pub mod stmt;
mod weight;
mod check;
mod find;

pub use constraints::*;
pub use det::*;
pub use flag::*;
pub use generate::*;
pub use object::*;
pub use operator::*;
pub use rng::*;
pub use weight::*;

pub trait EnumKind {
    fn kind(&self) -> &'static str;
}

#[test]
fn test_generate_and_mutate() {
    use crate::FuzzProgram;
    use crate::Serialize;

    fn gen_and_mutate(target: &str) {
        for _ in 0..100 {
            let (mut p1, mut p2) = {
                let mut program = FuzzProgram::generate_program_for_func(target).unwrap();
                // make it like a seed
                program.parent = Some(0);
                println!("**p0**\n{}", program.serialize().unwrap());
                let p1 = program.clone();
                let p2 = program.clone();
                (p1, p2)
            };
            p1.mutate_program().unwrap();
            println!("**p1**\n{}", p1.serialize().unwrap());
            println!("**ops**: {}", p1.ops.serialize().unwrap());

            p2.mutate_program_by_ops(&p1.ops).unwrap();
            p2.refine_program().unwrap();
            println!("**p2**\n{}", p2.serialize().unwrap());

            assert_eq!(p1.serialize().unwrap(), p2.serialize().unwrap())
        }
    }

    gen_and_mutate("func_add");
    gen_and_mutate("func_create");
    gen_and_mutate("func_use");
    gen_and_mutate("func_struct");
}
