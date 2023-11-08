//! Deterministic mutation

use downcast_rs::Downcast;
use std::{collections::HashMap, fmt};

use crate::{MutateOperation, ObjectState};

type MutatingClosure<T> =
    Box<dyn Fn(&mut T, &mut ObjectState) -> (MutateOperation, DetAction) + Send + Sync>;

/// A warpper/caller that describes how to mutating a value
pub struct DetMutateCaller<T> {
    /// name
    pub name: &'static str,
    /// Mutating closure
    pub f: MutatingClosure<T>,
}

/// Deterministic Mutate Step
pub trait DetMutateStep: 'static + Downcast + Send + Sync + fmt::Debug {}

/// Object that has deterministic steps in mutation
pub trait DetMutate {
    /// Return its deterministic steps
    fn det_mutateion_steps() -> Vec<Box<dyn DetMutateStep>>;
}

downcast_rs::impl_downcast!(DetMutateStep);

// Caller has mutate step traits
impl<T: 'static + fmt::Debug> DetMutateStep for DetMutateCaller<T> {}

pub enum DetAction {
    Keep,
    Next,
    Last,
    Finish,
}
/// Call det step for object
/// first, we donwcast step to caller, and then invoke it with object and state.
/// finnaly, we check its return and move the `det_iter`, or mark det is done.
pub fn call_det<T: 'static + fmt::Debug + DetMutate>(
    obj: &mut T,
    state: &mut ObjectState,
    //  // f: &dyn DetMutateStep,
) -> eyre::Result<Option<MutateOperation>> {
    DET_CACHE.with(|cache| {
        if let Some((step, len)) = cache.borrow_mut().get_det_mutate_step::<T>(state) {
            //return Ok(state.as_mutate_operator(op));
            if let Some(caller) = step.downcast_ref::<DetMutateCaller<T>>() {
                let (op, next) = (caller.f)(obj, state);
                match next {
                    DetAction::Next => {
                        (*state.mutate).borrow_mut().next_det_iter();
                    }
                    DetAction::Last => {
                        crate::log!(trace, "move last det");
                        (*state.mutate).borrow_mut().set_det_iter(len - 1);
                    }
                    DetAction::Finish => {
                        crate::log!(trace, "done det");
                        state.done_deterministic();
                    }
                    _ => {}
                }
                return Ok(Some(op));
            }
            eyre::bail!("fail to call det function")
        }
        Ok(None)
    })
}

/// Add det steps. e.g.
///  add_det_mutation!(steps, MutateOperation::BitFlip, |n: T| Mutator::bit_flip_at(n, i));
#[macro_export]
macro_rules! add_det_mutation {
    ($steps:ident, $name:literal, |$n:ident: $ty:ty, $s:ident| $f:expr) => {
        $steps.push(Box::new($crate::fuzz::det::DetMutateCaller {
            name: $name,
            f: Box::new(move |$n: &mut $ty, $s: &mut ObjectState| $f),
        }));
    };
    ($steps:ident, $name:literal, |$n:ident: $ty:ty| $f:expr) => {
        $steps.push(Box::new($crate::fuzz::det::DetMutateCaller {
            name: $name,
            f: Box::new(move |$n: &mut $ty, _state: &mut ObjectState| $f),
        }));
    };
}

impl<T> fmt::Debug for DetMutateCaller<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetMutateCaller")
            .field("op", &self.name)
            .finish()
    }
}

use std::cell::RefCell;

thread_local! {
    static DET_CACHE:RefCell<DetMutateStepsCache> = RefCell::new(DetMutateStepsCache::default());
}

/// Cache of deterministic steps
#[derive(Default)]
pub struct DetMutateStepsCache {
    /// Key is type of object
    /// value is the list its steps
    map: HashMap<&'static str, Vec<Box<dyn DetMutateStep>>>,
}

impl DetMutateStepsCache {
    /// Get which step it should use
    /// `det_iter` in state is used to determine which step in the list it should use,
    pub fn get_det_mutate_step<T: DetMutate>(
        &mut self,
        state: &mut ObjectState,
    ) -> Option<(&dyn DetMutateStep, usize)> {
        if !state.is_deterministic() {
            return None;
        }
        let key = std::any::type_name::<T>();
        let det_steps = self
            .map
            .entry(key)
            .or_insert_with(|| T::det_mutateion_steps());
        let det_index = state.mutate.borrow().det_iter;
        let len = det_steps.len();
        assert!(det_index <= len, "det_index is large than len");
        crate::log!(
            trace,
            "type: {}, det index: {}, len: {}",
            std::any::type_name::<T>(),
            det_index,
            len
        );
        det_steps.get(det_index).map(|f| (f.as_ref(), len))
    }
}
