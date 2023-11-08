//! Describe what mutating did, which key it mutates, what operation it uses

use hopper_derive::{EnumKind, Serde};

use crate::{runtime::*, EnumKind, IrEntry, RngState};

/// Mutate operation,
/// represent different kind of mutating behaviors.
#[derive(Debug, Clone, Serde, EnumKind)]
pub enum MutateOperation {
    // ---- Integer ----
    /// Flip one bit
    IntBitFlip {
        index: u8,
    },
    /// Flip some bits
    IntFlip {
        indices: Vec<u8>,
    },
    /// Add
    IntAdd {
        change: u64,
    },
    /// Sub
    IntSub {
        change: u64,
    },
    /// Set int in range min..max
    IntRange {
        min: IrEntry,
        max: IrEntry,
    },
    /// Set as value
    IntSet {
        val: IrEntry,
    },
    /// Get the value
    IntGet,
    // Set cmp value
    IntCmp {
        val: u64,
    },
    // Set cmp or corpus value's variance
    IntVariance {
        val: u64,
    },
    // Set Random value
    IntRandom {
        val: u64,
    },
    /// Set value from corpus
    Corpus {
        index: usize,
    },
    // ----  Float ----
    /// Add Float
    FloatAdd {
        change: f32,
    },
    /// Float New
    FloatNew {
        val: f64,
    },
    // ---- Sequence ----
    /// set buffer from compare function
    BufCmp {
        offset: usize,
        buffer: Vec<u8>,
    },
    /// set buffer from seeds
    BufSeed {
        index: usize,
    },
    /// Refine buffer
    BufRefine {
        buffer: Vec<u8>,
    },
    /// Pad to a larger length with all zero
    VecPad {
        len: usize,
        zero: bool,
        rng_state: RngState,
    },
    /// Add elements
    VecAdd {
        offset: usize,
        len: usize,
        rng_state: RngState,
    },
    /// Delete elements
    VecDel {
        offset: usize,
        len: usize,
    },
    /// Slice two input buffer
    BufSplice {
        program_id: usize,
        stmt_index: usize,
        split_at: usize,
        range: Option<crate::SpliceRange>,
    },
    /// Havoc buffer
    BufHavoc {
        use_bytes: usize,
        swap: bool,
        op: Box<MutateOperator>,
    },
    UseDict {
        offset: usize,
        dict: Vec<u8>,
        is_insert: bool,
    },
    // ---- Pointer ---
    /// PointerTodo
    PointerTodo,
    /// Set pointer as NULL
    PointerNull,
    /// Use other location as pointer
    PointerUse {
        loc: Location,
    },
    /// Use return as pointer
    PointerRet {
        f_name: String,
        rng_state: RngState,
    },
    /// Generate non-null pointer
    PointerGen {
        rng_state: RngState,
    },
    /// Generate non-null char pointer
    PointerGenChar,
    /// Make poiter to an address of canary
    PointerCanary,
    /// Make pointer to an file name
    PointerFile {
        read: bool,
    },
    /// Make int to be a file descriptor
    FdFile,
    /// Generate and init opaque pointer
    InitOpaque {
        call_i: usize,
    },
    /// Generate and init opaque pointer for inference
    InitOpaqueForInfer {
        call_i: usize,
    },
    /// Remove Init opaque pointer
    RemoveInitOpaque,
    // ---- Function Pointer ----
    /// Find another function pointer
    FnPointer {
        f_name: String,
    },
    /// Try generate a totally new one for option
    OptionNew {
        rng_state: RngState,
    },
    /// Set None for option
    OptionNone,
    // ---- Function ----
    /// Find another function pointer
    /// Change call argument
    CallArg {
        arg_pos: usize,
        rng_state: RngState,
    },
    EffCallArg {
        arg_pos: usize,
        eff_i: usize,
        rng_state: RngState,
    },
    NewTarget {
        f_name: String,
        arg_i: Option<usize>,
    },
    /// Insert implicit call
    CallImplicitInsert {
        f_name: String,
        rng_state: RngState,
    },
    /// Insert related call
    CallRelatedInsert {
        f_name: String,
        arg_pos: usize,
        rng_state: RngState,
    },
    InitTypeWithCall,
    /// Update call return
    CallUpdate {
        fields: LocFields,
        ops: Vec<MutateOperator>,
    },
    // ---- Other ----
    /// Flip boolean type
    FlipBool,
    /// Generate a new union instance
    UnionNew {
        rng_state: RngState,
    },
    /// Generate a new union with a specific member
    UnionUse {
        rng_state: RngState,
        member: String,
    },
    /// Do nothing, or indicating you should ending the stage
    Nop,
}

impl MutateOperation {
    pub fn is_arithmetical(&self) -> bool {
        matches!(
            self,
            Self::IntBitFlip { index: _ }
                | Self::IntFlip { indices: _ }
                | Self::IntAdd { change: _ }
                | Self::IntSub { change: _ }
                | Self::Corpus { index: _ }
                | Self::FloatAdd { change: _ }
                | Self::FloatNew { val: _ }
        )
    }

    pub fn is_pointer_todo(&self) -> bool {
        matches!(self, Self::PointerTodo)
    }

    pub fn is_nop(&self) -> bool {
        matches!(self, MutateOperation::Nop)
    }
}

/// Mutate operator,
/// using operation on certain objet field
#[derive(Debug, Clone, Serde)]
pub struct MutateOperator {
    /// key of object field
    pub key: WeakLocation,
    /// is deterministic
    pub det: bool,
    /// operation
    pub op: MutateOperation,
}

impl MutateOperator {
    /// Create an operator
    pub fn new(key: Location, op: MutateOperation) -> Self {
        let key = key.to_weak_loc();
        Self {
            key,
            det: false,
            op,
        }
    }

    pub fn stmt_op(op: MutateOperation) -> Self {
        Self {
            key: WeakLocation::null(),
            det: false,
            op,
        }
    }

    /// Create a nop operator
    pub fn nop() -> Self {
        Self {
            key: WeakLocation::null(),
            det: false,
            op: MutateOperation::Nop,
        }
    }

    /// Is the operation is nop or not
    pub fn is_nop(&self) -> bool {
        self.op.is_nop()
    }

    /// Set index after mutation
    pub fn set_index(&mut self, index: StmtIndex) {
        if !self.is_nop() {
            self.key.set_index(index);
        }
    }
}

impl std::fmt::Display for MutateOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({}: {})",
            self.key.serialize().unwrap(),
            self.op.serialize().unwrap(),
        )
    }
}

impl CloneProgram for MutateOperator {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        Self {
            key: self.key.clone_with_program(program),
            op: self.op.clone_with_program(program),
            det: self.det,
        }
    }
}

impl CloneProgram for MutateOperation {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        match self {
            MutateOperation::PointerUse { loc } => MutateOperation::PointerUse {
                loc: loc.clone_with_program(program),
            },
            MutateOperation::BufHavoc {
                use_bytes,
                swap,
                op,
            } => MutateOperation::BufHavoc {
                use_bytes: *use_bytes,
                swap: *swap,
                op: Box::new(op.clone_with_program(program)),
            },
            MutateOperation::CallUpdate { fields, ops } => {
                let new_list = ops
                    .iter()
                    .map(|op| op.clone_with_program(program))
                    .collect();
                MutateOperation::CallUpdate {
                    fields: fields.clone(),
                    ops: new_list,
                }
            }
            _ => self.clone(),
        }
    }
}

impl CloneProgram for Vec<MutateOperator> {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        let mut ops = vec![];
        for op in self {
            if !op.key.is_released() {
                let op = op.clone_with_program(program);
                // exclude those operators involved with tmp indices
                if let Some(index) = &op.key.stmt_index {
                    let uniq = index.get_uniq();
                    if program
                        .tmp_indices
                        .iter()
                        .any(|tmp_i| tmp_i.get_uniq() == uniq)
                    {
                        continue;
                    }
                }
                ops.push(op);
            }
        }
        ops
    }
}

impl Serialize for Box<MutateOperator> {
    fn serialize(&self) -> eyre::Result<String> {
        self.as_ref().serialize()
    }
}

impl Deserialize for Box<MutateOperator> {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        Ok(Box::new(MutateOperator::deserialize(de)?))
    }
}

#[derive(Debug, Clone, Serde)]

pub struct SpliceRange {
    pub lower: usize,
    pub upper: usize,
    pub is_insert: bool,
}
