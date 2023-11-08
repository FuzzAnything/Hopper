//! Choose item in slice with weight.
//! The slice's item should implement `WeightedItem` trait.
//!

use crate::{
    fuzz::rng, FuzzProgram, FuzzStmt, LocFields, ObjectState, RcIndex, StmtIndex, TypeConstraint,
};

/// Define weight of a object
pub trait WeightedItem {
    fn get_weight(&self) -> usize {
        0
    }
}

pub fn get_weight_sum<T: WeightedItem>(items: &[T]) -> usize {
    let mut sum = 0;
    for item in items {
        let w = item.get_weight();
        sum += w;
    }
    sum
}

/// Choose element in slice by weight
pub fn choose_weighted<T: WeightedItem>(items: &[T]) -> Option<usize> {
    if items.is_empty() {
        return None;
    }
    let mut weights = vec![];
    let mut sum = 0;
    for item in items {
        let w = item.get_weight();
        sum += w;
        weights.push(sum);
    }
    if sum == 0 {
        return None;
    }
    let choose = rng::gen_range(0..sum);
    crate::log!(trace, "slice weights: {:?}, choose: {}", weights, choose);
    weights.iter().position(|w| choose < *w)
}

/// Choose position based on state
pub fn choose_weighted_by_state(state: &ObjectState) -> Option<usize> {
    let mut weights = vec![];
    let mut sum = 0;
    for item in &state.children {
        let w = item.mutate.borrow().get_weight();
        sum += w;
        weights.push(sum);
    }
    if sum == 0 {
        return None;
    }
    let choose = rng::gen_range(0..sum);
    crate::log!(trace, "state weights: {:?}, choose: {}", weights, choose);
    weights.iter().position(|w| choose < *w)
}

impl FuzzProgram {
    /// Update statements' weight from bottom to top
    /// If the field or arg has constraints and fixed, we set its weight to 0
    pub fn update_weight(&self) {
        for i in 0..self.stmts.len() {
            let stmt = &self.stmts[i].stmt;
            match stmt {
                FuzzStmt::Call(call) => {
                    crate::inspect_function_constraint_with(&call.name, |fc| {
                        for (i, fc) in fc.arg_constraints.iter().enumerate() {
                            let arg_index = &call.args[i];
                            self.update_type_weight(arg_index, fc, None);
                        }
                        Ok(())
                    })
                    .unwrap();
                }
                FuzzStmt::Load(load) => {
                    if load.is_const {
                        let _ = load.state.replace_weight(0);
                    }
                    crate::iterate_type_constraint_with(|ty, tc| {
                        if tc
                            .list
                            .iter()
                            .any(|item| item.constraint.should_not_mutate())
                        {
                            let stmt_index = &self.stmts[i].index;
                            let locs_containing_ty =
                                load.state.find_fields_with(|s| s.ty == ty, false);
                            for prefix in locs_containing_ty {
                                self.update_type_weight(stmt_index, tc, Some(prefix));
                            }
                        }
                        Ok(())
                    })
                    .unwrap();
                }
                _ => {}
            }
        }
    }

    fn update_type_weight(
        &self,
        stmt_index: &StmtIndex,
        tc: &TypeConstraint,
        prefix: Option<LocFields>,
    ) {
        let prefix = prefix.unwrap_or_default();
        for item in tc.list.iter() {
            if item.constraint.should_not_mutate() {
                let loc = item.key.to_loc_for_refining(self, stmt_index, &prefix);
                if loc.is_none() {
                    continue;
                }
                let loc = loc.unwrap();
                if let FuzzStmt::Load(load) = &self.stmts[loc.stmt_index.unwrap().get()].stmt {
                    let sub_state = load
                        .state
                        .get_child_by_fields(loc.fields.as_slice())
                        .unwrap();
                    let _ = sub_state.replace_weight(0);
                    load.state.update_weight_from_children();
                }
            }
        }
    }
}

impl ObjectState {
    /// Update weight based on its children's weights
    pub fn update_weight_from_children(&self) -> usize {
        if self.children.is_empty() {
            return self.mutate.borrow().get_weight();
        }
        let sum = self
            .children
            .iter()
            .map(|s| s.update_weight_from_children())
            .sum();

        // anneal children's weight
        self.mutate.borrow_mut().set_weight(1 + sum / 2);
        sum
    }

    /// Replace weight with the new value
    pub fn replace_weight(&self, new_weight: usize) -> usize {
        if new_weight == 0 {
            self.done_deterministic();
        }
        let mut mutate = self.mutate.borrow_mut();
        let weight = mutate.get_weight();
        if weight != new_weight {
            mutate.set_weight(new_weight);
        }
        weight
    }
}
