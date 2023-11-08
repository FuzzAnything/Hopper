//! Optional feature
//! used for slice API calls from real-world code, and use them as Hopper's input.

use eyre::{ContextCompat, Report, Result, WrapErr};
use once_cell::sync::OnceCell;
use std::{
    cell::RefCell,
    collections::HashMap,
    hash::{Hash, Hasher},
    rc::{Rc, Weak},
};

pub type NodeTy = Rc<RefCell<TreeNode>>;
pub type ApiTreeTy = HashMap<String, NodeTy>;
// API_TREE: A parent-childs tree which records the call relationship between APIs.
//     Key: c-style type,  Value: TreeNode (value-sensitive)
//     Example: two slice of type "cJSON *": "A(v_0) B(v_1) C(v_3) D(v_4)" and "A(0) B(v_2) B(v_2) C(v_3)"
//     API_TREE["cJSON *"] = Node(A(v_0)) -> Node(B(v_1)) -> Node(C(v_3)) -> Node(D(v_4))
//                                        -> Node(B(v_2)) -> Node(B(v_2)) -> Node(C(v_3))
pub fn get_slices_path() -> Option<String> {
    pub static SLICES_ENV: OnceCell<Option<String>> = OnceCell::new();
    SLICES_ENV
        .get_or_init(|| std::env::var(crate::SLICES_PATH).ok())
        .clone()
}

pub fn is_using_slice() -> bool {
    get_slices_path().is_some()
}

// if ONLY_USE_SLICES_VAR is set: generate program only by slices, which means the func without slices will not be generated with program.
// Otherwise, the func without slices will be generated randomly.
// pub fn is_only_using_slics() -> bool {
//     pub static ONLY_USE_SLICE_ENV: OnceCell<bool> = OnceCell::new();
//     *ONLY_USE_SLICE_ENV.get_or_init(|| std::env::var(crate::ONLY_USE_SLICES_VAR).is_ok())
// }

pub fn get_api_tree() -> Option<&'static ApiTreeTy> {
    pub static mut API_TREE: OnceCell<Option<ApiTreeTy>> = OnceCell::new();
    if let Some(path) = get_slices_path() {
        let api_tree = unsafe {
            API_TREE.get_or_init(|| {
                Some(slice_utils::read_api_slices(path).expect("expect to get a non-none api tree"))
            })
        };
        return api_tree.as_ref();
    }
    None
}

fn get_func_node_map() -> &'static HashMap<String, Vec<NodeTy>> {
    pub static mut FUNC_NODE_MAP: OnceCell<HashMap<String, Vec<NodeTy>>> = OnceCell::new();
    let func_node_map = unsafe { FUNC_NODE_MAP.get_or_init(slice_utils::init_func_node_map) };
    func_node_map
}

pub fn is_func_in_slice(f_name: &str) -> bool {
    let func_node_map = get_func_node_map();
    if func_node_map.contains_key(f_name) {
        return true;
    }
    false
}

// Structure to represent a function node in a tree.
#[derive(Default, Debug, Clone)]
pub struct TreeNode {
    pub is_root: bool,
    pub childs: Vec<NodeTy>,
    pub parent: Weak<RefCell<TreeNode>>,
    pub index: Option<usize>, // the dataflow related arg index
    pub func: Function,
}

impl TreeNode {
    pub fn set_func(&mut self, func: Function) {
        self.func = func;
    }

    pub fn set_parent(&mut self, parent: Weak<RefCell<TreeNode>>) {
        self.parent = parent;
    }

    pub fn set_root(&mut self, is_root: bool) {
        self.is_root = is_root;
    }

    pub fn _set_childs(&mut self, childs: Vec<NodeTy>) {
        self.childs = childs;
    }

    pub fn push_child(&mut self, child: NodeTy) {
        self.childs.push(child);
    }

    pub fn set_index(&mut self, index: Option<usize>) {
        self.index = index;
    }
}

#[derive(Debug, Clone)]
pub struct Param {
    pub cvrmask: u64,
    pub param_name: String,
    pub param_type: String,
    pub raw_param_type: String,
}

#[derive(Debug, Clone)]
pub struct Arg {
    pub cvrmask: u64,
    pub arg_name: String,
    pub arg_type: String,
    pub raw_arg_type: String,
    pub value: ArgValue,
}

#[derive(Debug, Clone)]
pub struct FloatValue(f64);
impl FloatValue {
    fn key(&self) -> u64 {
        self.0.to_bits()
    }
    fn value(&self) -> f64 {
        self.0
    }
}
impl Hash for FloatValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key().hash(state);
    }
}

impl PartialEq for FloatValue {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for FloatValue {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    Integer(i64),
    Float(FloatValue),
    Character(u8),
    StringValue(String),
    NULLPointer,
    None,
}

#[derive(Debug, Clone, Default)]
pub struct Function {
    pub cvrmask: u64,
    pub call: Vec<Arg>,
    pub decl: Vec<Param>,
    pub func_name: String,
    pub ret_type: String,
    pub raw_ret_type: String,
    pub t_index: i64,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SliceError {
    #[error("The function `{0}` is not found in slices.")]
    SliceNotFound(String),
    #[error("The function `{0}` is not found in gadgets.")]
    GadgetNotFound(String),
    #[error("Attempt to access a invalid `{1}`-th arg of `{0}`.")]
    ArgIndexError(String, usize),
    #[error(
        "Error to insert the possible free func {1} which is the child of {0} as dyn call context."
    )]
    InsertFreeError(String, String),
    #[error("Error to parse the input: {0}")]
    ParseError(String),
}

pub fn is_slice_not_found_err<T>(res: &Result<T>) -> bool {
    if let Err(e) = res {
        if let Some(SliceError::SliceNotFound(_)) = e.downcast_ref::<SliceError>() {
            return true;
        }
    }
    false
}

pub fn is_arg_index_err(res: Option<Report>) -> Result<bool> {
    if let Some(e) = res {
        if let Some(SliceError::ArgIndexError(_, _)) = e.downcast_ref::<SliceError>() {
            return Ok(true);
        }
        // return other errs
        return Err(e);
    }
    // not err
    Ok(false)
}

pub mod slice_utils {
    use super::*;
    use regex::Regex;
    use serde_json::Value;
    use std::collections::VecDeque;

    // Parse the raw string to a vector of api slices.
    pub fn parse_to_api_slices(str: String) -> Vec<Vec<String>> {
        let mut api_slices: Vec<Vec<String>> = Vec::new();
        let mut api_slice: Vec<String> = Vec::new();
        for line in str.lines() {
            let line = line.trim();
            if line.is_empty() {
                api_slices.push(api_slice);
                api_slice = Vec::new();
            } else {
                api_slice.push(line.to_string());
            }
        }
        if api_slice.len() > 1 {
            api_slices.push(api_slice);
        }
        crate::log!(trace, "slices: {api_slices:?}");
        api_slices
    }

    // unify array type to pointer type. like, char[100][33] to char **.
    pub fn unify_arg_type(arg_type: String) -> String {
        let re = Regex::new(r"(\[\d+\])").unwrap();
        let arg_type = re.replace(&arg_type, " *").to_string();
        let ary_type = re.replace_all(&arg_type, "*").to_string();
        ary_type
    }

    // Parse a arg string to (arg_type, arg_name), like "cJSON *root" to ("cJSON *", "root")
    pub fn parse_api_arg(arg_string: String, arg_json: Option<Value>) -> Result<Arg> {
        let err: SliceError;
        let arg = if let Some(arg) = &arg_json {
            err = SliceError::ParseError(format!("{arg_json:?}"));
            arg.clone()
        } else {
            err = SliceError::ParseError(arg_string.clone());
            serde_json::from_str(&arg_string)?
        };

        Ok(Arg {
            cvrmask: arg["CVRMask"]
                .as_u64()
                .ok_or_else(|| Report::new(err.clone()))?,
            arg_name: arg["arg_name"]
                .as_str()
                .ok_or_else(|| Report::new(err.clone()))?
                .to_string(),
            arg_type: unify_arg_type(
                arg["arg_type"]
                    .as_str()
                    .ok_or_else(|| Report::new(err.clone()))?
                    .to_string(),
            ),
            raw_arg_type: unify_arg_type(
                arg["raw_arg_type"]
                    .as_str()
                    .ok_or_else(|| Report::new(err.clone()))?
                    .to_string(),
            ),
            value: match &arg["value"] {
                Value::Number(v) => {
                    if v.is_i64() {
                        let arg_name = arg["arg_name"]
                            .as_str()
                            .ok_or_else(|| Report::new(err.clone()))?;
                        if arg_name == "<Char>" {
                            ArgValue::Character(v.as_u64().ok_or_else(|| Report::new(err))? as u8)
                        } else if arg_name == "<NULL>" {
                            ArgValue::NULLPointer
                        } else if arg_name == "<Int>" {
                            ArgValue::Integer(v.as_i64().ok_or_else(|| Report::new(err))?)
                        } else {
                            ArgValue::None
                        }
                    } else if v.is_f64() {
                        ArgValue::Float(FloatValue(v.as_f64().ok_or_else(|| Report::new(err))?))
                    } else if v.is_u64() {
                        ArgValue::Integer(v.as_i64().ok_or_else(|| Report::new(err))?)
                    } else {
                        return Err(Report::new(SliceError::ParseError(format!(
                            "Invalid arg value `{v:?}`"
                        ))));
                    }
                }
                Value::String(s) => ArgValue::StringValue(s.clone()),
                _ => {
                    return Err(Report::new(SliceError::ParseError(format!(
                        "Invalid arg value `{:?}`",
                        arg["value"]
                    ))))
                }
            },
        })
    }

    pub fn parse_api_param(param_json: Value) -> Result<Param> {
        let err = SliceError::ParseError(format!("{param_json:?}"));
        let param: Value = param_json;

        Ok(Param {
            cvrmask: param["CVRMask"]
                .as_u64()
                .ok_or_else(|| Report::new(err.clone()))?,
            param_name: param["param_name"]
                .as_str()
                .ok_or_else(|| Report::new(err.clone()))?
                .to_string(),
            param_type: param["param_type"]
                .as_str()
                .ok_or_else(|| Report::new(err.clone()))?
                .to_string(),
            raw_param_type: param["raw_param_type"]
                .as_str()
                .ok_or_else(|| Report::new(err))?
                .to_string(),
        })
    }

    pub fn parse_api_fn(func_str: String) -> Result<Function> {
        let func: Value = serde_json::from_str(func_str.trim())?;
        let err = SliceError::ParseError(func_str);
        let mut call: Vec<Arg> = Vec::new();
        let mut decl: Vec<Param> = Vec::new();
        let call_json = func["Call"]
            .as_array()
            .ok_or_else(|| Report::new(err.clone()))?;
        for value in call_json {
            let arg = parse_api_arg(String::new(), Some(value.clone()))?;
            call.push(arg);
        }

        let decl_json = func["Decl"]
            .as_array()
            .ok_or_else(|| Report::new(err.clone()))?;
        for value in decl_json {
            let param = parse_api_param(value.clone())?;
            decl.push(param);
        }

        Ok(Function {
            cvrmask: func["CVRMask"]
                .as_u64()
                .ok_or_else(|| Report::new(err.clone()))?,
            call,
            decl,
            func_name: func["func_name"]
                .as_str()
                .ok_or_else(|| Report::new(err.clone()))?
                .to_string(),
            ret_type: func["ret_type"]
                .as_str()
                .ok_or_else(|| Report::new(err.clone()))?
                .to_string(),
            raw_ret_type: func["raw_ret_type"]
                .as_str()
                .ok_or_else(|| Report::new(err.clone()))?
                .to_string(),
            t_index: func["t_index"].as_i64().ok_or_else(|| Report::new(err))?,
        })
    }

    fn has_same_value(func1: &Function, func2: &Function) -> bool {
        if func1.call.len() != func2.call.len() {
            return false;
        }
        for index in 0..func1.call.len() {
            let arg1 = &func1.call[index];
            let arg2 = &func2.call[index];
            if arg1.value != arg2.value {
                return false;
            }
        }
        true
    }

    // Get the index of arg in func.
    pub fn get_api_arg_index(func: &Function) -> Option<usize> {
        let index = func.t_index;
        if index == -1 {
            None
        } else {
            Some(index as usize)
        }
    }

    // Insert to function to the API_TREE, and reuturn the node of this funciton.
    pub fn insert_fn_to_tree(_layer: i32, func: Function, parent: NodeTy) -> Result<NodeTy> {
        // if find an existing node in parent.childs, return it
        for child in parent.borrow().childs.iter() {
            if child.borrow().func.func_name == func.func_name
                && has_same_value(&child.borrow().func, &func)
            {
                return Ok(child.clone());
            }
        }

        // if not find, create a new node and insert it to parent.childs
        let new_node = Rc::new(RefCell::new(TreeNode::default()));
        let index = get_api_arg_index(&func);

        new_node.borrow_mut().set_index(index);
        (*new_node.borrow_mut()).set_func(func);
        (*new_node.borrow_mut()).set_parent(Rc::downgrade(&parent));
        (*new_node.borrow_mut()).set_root(false);
        (*parent.borrow_mut()).push_child(new_node.clone());

        Ok(new_node)
    }

    // Insert a slice of functions to the API_TREE.
    pub fn insert_fns_to_tree(api_slice: Vec<String>, root: Rc<RefCell<TreeNode>>) -> Result<()> {
        let mut parent = root;
        let mut curr_node: Rc<RefCell<TreeNode>>;
        let mut layer = 0;
        for api in api_slice {
            if api.starts_with('#') || api.trim().is_empty() {
                continue;
            }
            layer += 1;
            let func = parse_api_fn(api)?;
            curr_node = insert_fn_to_tree(layer, func, parent)?;
            parent = curr_node;
        }
        Ok(())
    }

    // Insert one api slice to the API_TREE.
    pub fn insert_one_api_slice(api_slice: Vec<String>, api_tree: &mut ApiTreeTy) -> Result<()> {
        let first_arg = api_slice[0].clone();
        let taint_arg = parse_api_arg(first_arg, None)?;
        let arg_type = taint_arg.arg_type;
        if let Some(root_node) = api_tree.get(&arg_type) {
            insert_fns_to_tree(api_slice[1..].to_vec(), root_node.clone())
        } else {
            let root_node = Rc::new(RefCell::new(TreeNode::default()));
            (*root_node.borrow_mut()).set_root(true);
            insert_fns_to_tree(api_slice[1..].to_vec(), root_node.clone())?;
            api_tree.insert(arg_type, root_node);
            Ok(())
        }
    }

    // Read and parse the api_slice to the API_TREE.
    pub fn read_api_slices(slice_path: String) -> Result<ApiTreeTy> {
        crate::log!(
            info,
            "read api slices: this step will cost little minutes if your slice number is large."
        );
        let contents = std::fs::read_to_string(slice_path)
            .context("Invalid file path of input slices.".to_string())?;
        let api_slices = parse_to_api_slices(contents);
        let mut api_tree: ApiTreeTy = HashMap::new();
        for api_slice in api_slices {
            insert_one_api_slice(api_slice, &mut api_tree)?;
        }
        Ok(api_tree)
    }

    // Use the BFS way to traverse the given tree, and return the nodes which have the same func_name.
    pub fn bfs_get_func_nodes(func_name: &str, root: Rc<RefCell<TreeNode>>) -> Vec<NodeTy> {
        let mut queue: VecDeque<NodeTy> = VecDeque::new();
        let mut func_nodes: Vec<NodeTy> = Vec::new();
        queue.push_back(root);
        while !queue.is_empty() {
            let curr_node = queue.pop_front().unwrap();
            if curr_node.borrow().func.func_name == func_name {
                func_nodes.push(curr_node.clone());
            }
            for child in curr_node.borrow().childs.iter() {
                queue.push_back(child.clone());
            }
        }
        func_nodes
    }

    // Use the BFS way to traverse the given tree, and insert the meet node.
    pub fn bfs_init_root_tree(
        func_node_map: &mut HashMap<String, Vec<NodeTy>>,
        root: Rc<RefCell<TreeNode>>,
    ) {
        let mut queue: VecDeque<NodeTy> = VecDeque::new();
        queue.push_back(root);
        while !queue.is_empty() {
            let curr_node = queue.pop_front().unwrap();
            let func_name = &curr_node.borrow().func.func_name;
            if let Some(node_vec) = func_node_map.get_mut(func_name) {
                node_vec.push(curr_node.clone());
            } else {
                let node_vec: Vec<NodeTy> = vec![curr_node.clone()];
                func_node_map.insert(func_name.clone(), node_vec);
            }
            for child in curr_node.borrow().childs.iter() {
                queue.push_back(child.clone());
            }
        }
    }

    // Get the nodes which have the same func_name in the API_TREE.
    pub fn get_func_nodes(func_name: &str) -> Option<Vec<NodeTy>> {
        let api_tree = get_api_tree().expect("expect to get a non-none api tree");
        let mut func_nodes: Vec<NodeTy> = Vec::new();
        for (_, root) in api_tree.iter() {
            let mut nodes = bfs_get_func_nodes(func_name, root.clone());
            func_nodes.append(&mut nodes);
        }
        if !func_nodes.is_empty() {
            return Some(func_nodes);
        }
        None
    }

    pub fn init_func_node_map() -> HashMap<String, Vec<NodeTy>> {
        let mut func_node_map: HashMap<String, Vec<NodeTy>> = HashMap::new();
        let api_tree = get_api_tree().expect("expect to get a non-none api tree");
        for (_, root) in api_tree.iter() {
            bfs_init_root_tree(&mut func_node_map, root.clone());
        }
        func_node_map
    }

    // recursively get the parent nodes of the node.
    pub fn get_parent_nodes_recursively(node: Option<NodeTy>) -> Vec<NodeTy> {
        let mut parents: Vec<NodeTy> = Vec::new();
        if node.is_none() {
            return parents;
        }
        let node = node.unwrap();
        let mut parent = node.borrow().parent.upgrade();
        while parent.is_some() {
            let cur_node = parent.unwrap();
            if cur_node.borrow().is_root {
                break;
            }
            parents.push(cur_node.clone());
            parent = cur_node.borrow().parent.upgrade();
        }
        parents
    }

    // choose a node at API_TREE where has the same {func_name} and {index}.
    pub fn rand_choose_func_index_node(func_name: &str, index: usize) -> Option<NodeTy> {
        if let Some(func_nodes) = get_func_node_map().get(&func_name.to_string()) {
            crate::log!(trace, "Get the func node map.");
            let func_nodes: Vec<NodeTy> = func_nodes
                .iter()
                .filter(|node| {
                    node.borrow().index.is_some() && node.borrow().index.unwrap() == index
                })
                .cloned()
                .collect();
            crate::log!(trace, "Get the func nodes.");
            if func_nodes.is_empty() {
                return None;
            }
            let rand_index = crate::gen_range(0..func_nodes.len());
            let node = func_nodes[rand_index].clone();
            return Some(node);
        }
        None
    }

    pub fn _verbose_node(node: Rc<RefCell<TreeNode>>) {
        print!("{:#?} ", node.borrow());
    }

    pub fn _verbose_api_tree() {
        let api_tree = get_api_tree().expect("expect to get a non-none api tree");
        for (arg_type, root_node) in api_tree {
            println!("arg_type: {arg_type}");
            _verbose_node(root_node.clone());
        }
    }
    /* The human-readable test case are formated bellow, where the third call and some arg values are different.
        "$int *,arr
        void *,CRYPTO_malloc,int *,arr,char *,<String>,int,538
        int,BN_GF2m_poly2arr,const BIGNUM *,p,int *,arr,int,max
        int,BN_GF2m_mod_mul_arr,BIGNUM *,r,const BIGNUM *,a,const BIGNUM *,b,int *,arr,BN_CTX *,ctx
        void,CRYPTO_free,int *,arr,char *,<String>,int,<Int>

        $int *,arr
        void *,CRYPTO_malloc,int *,arr,char *,<String>,int,476
        int,BN_GF2m_poly2arr,const BIGNUM *,NULL,int *,arr,int,max
        int,BN_GF2m_mod_sqrt_arr,BIGNUM *,r,const BIGNUM *,a,int *,arr,BN_CTX *,ctx
        void,CRYPTO_free,int *,arr,char *,<String>,int,<Int>";
    */
    #[cfg(test)]
    static TEST_SLICES: &str = r#"{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":0,"arg_name":"<String>","arg_type":"char *","raw_arg_type":"char *","value":"/home/loydlv/vbd/hopper_bench/openssl/src/crypto/bn/bn_gf2m.c"},{"CVRMask":0,"arg_name":"<Int>","arg_type":"int","raw_arg_type":"int","value":538}],"Decl":[{"CVRMask":0,"param_name":"num","param_type":"size_t","raw_param_type":"unsigned long"},{"CVRMask":0,"param_name":"file","param_type":"const char *","raw_param_type":"const char *"},{"CVRMask":0,"param_name":"line","param_type":"int","raw_param_type":"int"}],"func_name":"CRYPTO_malloc","raw_ret_type":"void *","ret_type":"void *","t_index":-1}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"p","arg_type":"const BIGNUM *","raw_arg_type":"const struct bignum_st *","value":0},{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":1,"arg_name":"max","arg_type":"int","raw_arg_type":"int","value":0}],"Decl":[{"CVRMask":0,"param_name":"a","param_type":"const BIGNUM *","raw_param_type":"const struct bignum_st *"},{"CVRMask":0,"param_name":"p","param_type":"int *","raw_param_type":"int *"},{"CVRMask":0,"param_name":"max","param_type":"int","raw_param_type":"int"}],"func_name":"BN_GF2m_poly2arr","raw_ret_type":"int","ret_type":"int","t_index":1}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"r","arg_type":"BIGNUM *","raw_arg_type":"struct bignum_st *","value":0},{"CVRMask":0,"arg_name":"a","arg_type":"const BIGNUM *","raw_arg_type":"const struct bignum_st *","value":0},{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":0,"arg_name":"ctx","arg_type":"BN_CTX *","raw_arg_type":"struct bignum_ctx *","value":0}],"Decl":[{"CVRMask":0,"param_name":"r","param_type":"BIGNUM *","raw_param_type":"struct bignum_st *"},{"CVRMask":0,"param_name":"a","param_type":"const BIGNUM *","raw_param_type":"const struct bignum_st *"},{"CVRMask":0,"param_name":"p","param_type":"const int *","raw_param_type":"const int *"},{"CVRMask":0,"param_name":"ctx","param_type":"BN_CTX *","raw_param_type":"struct bignum_ctx *"}],"func_name":"BN_GF2m_mod_sqr_arr","raw_ret_type":"int","ret_type":"int","t_index":2}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":0,"arg_name":"<String>","arg_type":"char *","raw_arg_type":"char *","value":"/home/loydlv/vbd/hopper_bench/openssl/src/crypto/bn/bn_gf2m.c"},{"CVRMask":0,"arg_name":"<Int>","arg_type":"int","raw_arg_type":"int","value":551}],"Decl":[{"CVRMask":0,"param_name":"ptr","param_type":"void *","raw_param_type":"void *"},{"CVRMask":0,"param_name":"file","param_type":"const char *","raw_param_type":"const char *"},{"CVRMask":0,"param_name":"line","param_type":"int","raw_param_type":"int"}],"func_name":"CRYPTO_free","raw_ret_type":"void","ret_type":"void","t_index":0}
    
    {"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":0,"arg_name":"<String>","arg_type":"char *","raw_arg_type":"char *","value":"/home/loydlv/vbd/hopper_bench/openssl/src/crypto/bn/bn_gf2m.c"},{"CVRMask":0,"arg_name":"<Int>","arg_type":"int","raw_arg_type":"int","value":476}],"Decl":[{"CVRMask":0,"param_name":"num","param_type":"size_t","raw_param_type":"unsigned long"},{"CVRMask":0,"param_name":"file","param_type":"const char *","raw_param_type":"const char *"},{"CVRMask":0,"param_name":"line","param_type":"int","raw_param_type":"int"}],"func_name":"CRYPTO_malloc","raw_ret_type":"void *","ret_type":"void *","t_index":-1}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"<NULL>","arg_type":"const BIGNUM *","raw_arg_type":"const struct bignum_st *","value":0},{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":1,"arg_name":"max","arg_type":"int","raw_arg_type":"int","value":0}],"Decl":[{"CVRMask":0,"param_name":"a","param_type":"const BIGNUM *","raw_param_type":"const struct bignum_st *"},{"CVRMask":0,"param_name":"p","param_type":"int *","raw_param_type":"int *"},{"CVRMask":0,"param_name":"max","param_type":"int","raw_param_type":"int"}],"func_name":"BN_GF2m_poly2arr","raw_ret_type":"int","ret_type":"int","t_index":1}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"r","arg_type":"BIGNUM *","raw_arg_type":"struct bignum_st *","value":0},{"CVRMask":0,"arg_name":"a","arg_type":"const BIGNUM *","raw_arg_type":"const struct bignum_st *","value":0},{"CVRMask":0,"arg_name":"b","arg_type":"const BIGNUM *","raw_arg_type":"const struct bignum_st *","value":0},{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":0,"arg_name":"ctx","arg_type":"BN_CTX *","raw_arg_type":"struct bignum_ctx *","value":0}],"Decl":[{"CVRMask":0,"param_name":"r","param_type":"BIGNUM *","raw_param_type":"struct bignum_st *"},{"CVRMask":0,"param_name":"a","param_type":"const BIGNUM *","raw_param_type":"const struct bignum_st *"},{"CVRMask":0,"param_name":"b","param_type":"const BIGNUM *","raw_param_type":"const struct bignum_st *"},{"CVRMask":0,"param_name":"p","param_type":"const int *","raw_param_type":"const int *"},{"CVRMask":0,"param_name":"ctx","param_type":"BN_CTX *","raw_param_type":"struct bignum_ctx *"}],"func_name":"BN_GF2m_mod_mul_arr","raw_ret_type":"int","ret_type":"int","t_index":3}
    {"CVRMask":0,"Call":[{"CVRMask":0,"arg_name":"arr","arg_type":"int *","raw_arg_type":"int *","value":0},{"CVRMask":0,"arg_name":"<String>","arg_type":"char *","raw_arg_type":"char *","value":"/home/loydlv/vbd/hopper_bench/openssl/src/crypto/bn/bn_gf2m.c"},{"CVRMask":0,"arg_name":"<Int>","arg_type":"int","raw_arg_type":"int","value":489}],"Decl":[{"CVRMask":0,"param_name":"ptr","param_type":"void *","raw_param_type":"void *"},{"CVRMask":0,"param_name":"file","param_type":"const char *","raw_param_type":"const char *"},{"CVRMask":0,"param_name":"line","param_type":"int","raw_param_type":"int"}],"func_name":"CRYPTO_free","raw_ret_type":"void","ret_type":"void","t_index":0}
    "#;

    #[test]
    fn _test_parse_api_arg() -> Result<()> {
        let arg_str = r#"{"CVRMask":0,"arg_name":"monitor","arg_type":"cJSON *","raw_arg_type":"struct cJSON *","value":0}"#;
        let arg = parse_api_arg(arg_str.to_string(), None);
        println!("{arg:#?}");
        Ok(())
    }

    #[test]
    fn _test_parse_api_fn() -> Result<()> {
        let poly2arr_str = TEST_SLICES.lines().nth(8).unwrap().to_string();
        let func = parse_api_fn(poly2arr_str)?;
        assert_eq!(func.func_name, "BN_GF2m_poly2arr");
        assert_eq!(func.call.len(), 3);
        assert_eq!(func.call[0].value, ArgValue::NULLPointer);
        assert_eq!(func.call[1].value, ArgValue::None);
        Ok(())
    }

    #[test]
    fn _test_has_same_value() -> Result<()> {
        let malloc_1 = TEST_SLICES.lines().nth(1).unwrap().to_string();
        let malloc_2 = TEST_SLICES.lines().nth(7).unwrap().to_string();
        let mut malloc_1 = parse_api_fn(malloc_1)?;
        let malloc_2 = parse_api_fn(malloc_2)?;
        assert_eq!(malloc_1.call[2].value, ArgValue::Integer(538));
        assert_eq!(malloc_2.call[2].value, ArgValue::Integer(476));
        assert!(!has_same_value(&malloc_1, &malloc_2));
        malloc_1.call[2].value = ArgValue::Integer(476);
        assert!(has_same_value(&malloc_1, &malloc_2));
        Ok(())
    }

    #[test]
    fn _test_read_api_tree() -> Result<()> {
        let api_slices = parse_to_api_slices(TEST_SLICES.to_string());
        let mut api_tree: ApiTreeTy = HashMap::new();
        for api_slice in api_slices {
            insert_one_api_slice(api_slice, &mut api_tree)?;
        }
        let inner_type = "int *".to_string();
        assert!(api_tree.contains_key(&inner_type));
        let root_node = api_tree.get(&inner_type).unwrap();
        assert!(root_node.borrow().is_root);
        assert_eq!(root_node.borrow().childs.len(), 2);

        let malloc_node_1 = root_node.borrow().childs[0].clone();
        assert_eq!(malloc_node_1.borrow().childs.len(), 1);
        assert_eq!(malloc_node_1.borrow().index, None);

        let malloc_node_2 = root_node.borrow().childs[1].clone();
        assert_eq!(malloc_node_2.borrow().childs.len(), 1);
        assert_eq!(malloc_node_2.borrow().index, None);

        let poly2arr_node_1 = malloc_node_1.borrow().childs[0].clone();
        assert_eq!(poly2arr_node_1.borrow().index, Some(1));
        assert_eq!(poly2arr_node_1.borrow().childs.len(), 1);
        //_verbose_node(poly2arr_node.clone());

        let poly2arr_node_2 = malloc_node_2.borrow().childs[0].clone();
        assert_eq!(poly2arr_node_2.borrow().index, Some(1));
        assert_eq!(poly2arr_node_2.borrow().childs.len(), 1);

        let mod_mul_arr_node = poly2arr_node_1.borrow().childs[0].clone();
        let mod_sqrt_arr_node = poly2arr_node_2.borrow().childs[0].clone();
        assert_eq!(mod_mul_arr_node.borrow().childs.len(), 1);
        assert_eq!(mod_sqrt_arr_node.borrow().childs.len(), 1);

        let free_node_1 = mod_mul_arr_node.borrow().childs[0].clone();
        let free_node_2 = mod_sqrt_arr_node.borrow().childs[0].clone();
        assert_eq!(free_node_1.borrow().func.func_name, "CRYPTO_free");
        assert_eq!(free_node_2.borrow().func.func_name, "CRYPTO_free");
        Ok(())
    }
}

pub mod slice_fuzz {
    use super::*;
    use crate::{
        global_gadgets, log, runtime::CallStmt, utils, AssertStmt, FieldKey, FuzzProgram, LoadStmt,
        Location, ObjectState, StmtIndex,
    };
    use slice_utils::*;

    trait CastToParamType {
        fn cast_to_param_type(&self, param_type: &str) -> Result<crate::FuzzObject>;
    }

    macro_rules! impl_cast_integer_to_param_type {
        ($($name:ident),*) => {
            $(
                impl CastToParamType for $name{
                    fn cast_to_param_type(&self, param_type: &str) -> Result<crate::FuzzObject>{
                        match param_type{
                            "u8" => Ok(Box::new(*self as u8)),
                            "u16" => Ok(Box::new(*self as u16)),
                            "u32" => Ok(Box::new(*self as u32)),
                            "u64" => Ok(Box::new(*self as u64)),
                            "u128" => Ok(Box::new(*self as u128)),
                            "i8" => Ok(Box::new(*self as i8)),
                            "i16" => Ok(Box::new(*self as i16)),
                            "i32" => Ok(Box::new(*self as i32)),
                            "i64" => Ok(Box::new(*self as i64)),
                            "i128" => Ok(Box::new(*self as i128)),
                            "char" => Ok(Box::new(*self as u8 as char)),
                            "bool" => Ok(Box::new(*self != 0)),
                            "f32" => Ok(Box::new(*self as f32)),
                            "f64" => Ok(Box::new(*self as f64)),
                            _ => return Err(eyre::eyre!("error cast from {self} to {param_type}")),
                        }
                    }
                }
            )*
        };
    }

    macro_rules! impl_cast_floating_to_param_type {
        ($($name:ident),*) => {
            $(
                impl CastToParamType for $name{
                    fn cast_to_param_type(&self, param_type: &str) -> Result<crate::FuzzObject>{
                        match param_type{
                            "f32" => Ok(Box::new(*self as f32)),
                            "f64" => Ok(Box::new(*self as f64)),
                            _ => return Err(eyre::eyre!("error cast from {self} to {param_type}")),
                        }
                    }
                }
            )*
        };
    }

    impl_cast_integer_to_param_type!(i64, u64, u8);
    impl_cast_floating_to_param_type!(f64);

    impl FuzzProgram {
        pub fn generate_program_for_func_by_slices(
            f_name: &str,
        ) -> eyre::Result<Option<FuzzProgram>> {
            if crate::is_pilot_infer() || !is_using_slice() {
                return Ok(None);
            }
            // create an empty program
            let mut program: FuzzProgram = Default::default();
            program.save_mutate_state();
            let res = CallStmt::generate_new_by_slices(&mut program, CallStmt::TARGET, f_name, 0)
                .with_context(|| format!("fail to generate call `{f_name}`"));
            if is_slice_not_found_err(&res) {
                return Ok(None);
            }
            let mut call = res?;
            // only track target function
            call.track_cov = true;
            let _stmt = program.append_stmt(call);
            program.check_ref_use()?;
            program
                .refine_program()
                .with_context(|| program.serialize_all().unwrap())?;
            log!(trace, "Program after refine: {}", program.serialize_all()?);
            Ok(Some(program))
        }
    }

    fn is_gadget_exist(f_name: &str) -> bool {
        global_gadgets::get_instance()
            .get_func_gadget(f_name)
            .is_ok()
    }

    fn _verbose_parents(parents: &Vec<NodeTy>) {
        let mut parent_names = Vec::new();
        for i in (0..parents.len()).rev() {
            let parent = &parents[i];
            parent_names.push(parent.borrow().func.func_name.clone());
        }
        log!(trace, "parents: {:?}", parent_names);
    }

    fn generate_vec_with_given_value(state: &mut ObjectState, value: &String) -> Result<Vec<u8>> {
        let mut list = vec![];
        for unit in value.as_bytes() {
            let idx = state.children.len();
            let _ = state
                .add_child(idx, std::any::type_name::<u8>())
                .last_child_mut()?;
            list.push(*unit);
        }
        crate::fuzz::seq::add_vec_terminator(&mut list, state);
        Ok(list)
    }

    impl LoadStmt {
        fn generate_vec_with_str(
            str_value: &String,
            arg_type: &str,
            arg_ident: &str,
        ) -> Result<Self> {
            let mut state =
                LoadStmt::new_state(arg_ident, format!("alloc::vec::Vec<{arg_type}>").as_str());
            let value = generate_vec_with_given_value(&mut state, str_value)?;
            let load = LoadStmt::new(Box::new(value), state);
            Ok(load)
        }
    }

    impl CallStmt {
        pub fn generate_new_by_slices(
            program: &mut FuzzProgram,
            ident: &str,
            f_name: &str,
            depth: usize,
        ) -> eyre::Result<Self> {
            if !is_gadget_exist(f_name) {
                return Err(Report::new(SliceError::GadgetNotFound(f_name.to_string())));
            }
            if !is_func_in_slice(f_name) {
                // && is_only_using_slics()
                return Err(Report::new(SliceError::SliceNotFound(f_name.to_string())));
            }

            let fg = global_gadgets::get_instance()
                .get_func_gadget(f_name)?
                .clone();

            log!(
                trace,
                "Generate new call for {f_name} with slices. depth :{depth}, ident: {ident}."
            );
            let mut call = CallStmt::new(ident.to_string(), f_name.to_string(), fg);
            // Find or create args for call
            let type_names = call.fg.arg_types;
            let is_variadic = utils::is_variadic_function(type_names);
            let arg_num = if is_variadic {
                type_names.len() - 1
            } else {
                type_names.len()
            };

            for i in 0..arg_num {
                call.generate_ith_arg_by_slice(program, f_name, i, depth)?;
            }
            log!(trace, "Generate new call for {f_name} with slices done.");
            Ok(call)
        }

        fn set_ith_arg_as_null_pointer(
            &mut self,
            program: &mut FuzzProgram,
            index: usize,
        ) -> Result<()> {
            log!(
                trace,
                "set `{index}-th` arg of `{}` to a null pointer",
                self.fg.f_name
            );
            let arg_type = self.fg.arg_types[index];
            let arg_ident = self.fg.arg_idents[index];
            if !utils::is_pointer_type(arg_type) {
                return Err(eyre::eyre!("Unable to set NULL for non-pointer type arg"));
            }
            let null_stmt = LoadStmt::generate_null(arg_type, arg_ident)?;
            let stmt_index = program.insert_or_append_stmt(null_stmt)?;
            self.set_arg(index, stmt_index);
            Ok(())
        }

        // set ith arg with integer, floating or char type value.
        fn set_ith_arg_with_value(
            &mut self,
            program: &mut FuzzProgram,
            index: usize,
            val: crate::FuzzObject,
            arg_type: &str,
            arg_ident: &str,
        ) -> Result<()> {
            log!(
                trace,
                "`{}` set the `{index}-th` arg to {:?}",
                self.fg.f_name,
                val
            );
            let state = LoadStmt::new_state(arg_ident, arg_type);
            let load = LoadStmt::new(val, state);
            let stmt_index = program.insert_or_append_stmt(load)?;
            self.set_arg(index, stmt_index);
            Ok(())
        }

        // set ith arg with string type value.
        fn set_ith_arg_with_string(
            &mut self,
            program: &mut FuzzProgram,
            index: usize,
            val: &String,
        ) -> Result<()> {
            log!(
                trace,
                "`{}` set the `{index}-th` arg to {:?}",
                self.fg.f_name,
                val
            );
            let arg_type = self.fg.arg_types[index];
            let arg_ident = self.fg.arg_idents[index];
            if !utils::is_pointer_type(arg_type) {
                return Err(eyre::eyre!(
                    "Unable to set string value with non-pointer type!"
                ));
            }
            let mut state = LoadStmt::new_state(arg_ident, arg_type);
            let pointer_value = global_gadgets::get_instance()
                .get_object_builder(arg_type)?
                .generate_new(&mut state)?;
            // generate the vec stmt
            let load_stmt = LoadStmt::generate_vec_with_str(val, arg_type, arg_ident)?;
            let stmt_index = program.insert_or_append_stmt(load_stmt)?;
            //set pointer location
            let pointer = state.pointer.as_mut().context("pointer has ps")?;
            pointer.pointer_location = Location::stmt(stmt_index);
            // generate the pointer stmt
            //crate::pointer::generate_pointer_location(program, &mut state, 0)?;
            let pointer_load = LoadStmt::new(pointer_value, state);
            let load_index = program.insert_or_append_stmt(pointer_load)?;
            self.set_arg(index, load_index);
            Ok(())
        }

        fn set_ith_arg_ex_value(
            &mut self,
            program: &mut FuzzProgram,
            index: usize,
            arg: &Arg,
        ) -> Result<()> {
            if index >= self.fg.arg_idents.len() {
                return Err(Report::new(SliceError::ArgIndexError(
                    self.fg.f_name.to_string(),
                    index,
                )));
            }
            log!(
                trace,
                "set {index}-th arg of {} to {:?}",
                self.fg.f_name,
                arg
            );
            let arg_type = self.fg.arg_types[index];
            let arg_ident = self.fg.arg_idents[index];
            match &arg.value {
                ArgValue::None => return Ok(()),
                ArgValue::NULLPointer => self.set_ith_arg_as_null_pointer(program, index)?,
                ArgValue::Integer(int_val) => self.set_ith_arg_with_value(
                    program,
                    index,
                    int_val.cast_to_param_type(arg_type)?,
                    arg_type,
                    arg_ident,
                )?,
                ArgValue::Float(float_val) => self.set_ith_arg_with_value(
                    program,
                    index,
                    float_val.value().cast_to_param_type(arg_type)?,
                    arg_type,
                    arg_ident,
                )?,
                ArgValue::Character(char_val) => self.set_ith_arg_with_value(
                    program,
                    index,
                    char_val.cast_to_param_type(arg_type)?,
                    arg_type,
                    arg_ident,
                )?,
                ArgValue::StringValue(string_val) => {
                    self.set_ith_arg_with_string(program, index, string_val)?;
                }
            }
            Ok(())
        }

        // set current call args with the exact values in a slice
        fn set_arg_values_by_slice(
            &mut self,
            program: &mut FuzzProgram,
            node: NodeTy,
        ) -> Result<()> {
            for (index, arg) in node.borrow().func.call.iter().enumerate() {
                let res = self.set_ith_arg_ex_value(program, index, arg);
                if is_arg_index_err(res.err())? {
                    continue;
                }
            }
            Ok(())
        }

        fn generate_ith_arg_by_slice(
            &mut self,
            program: &mut FuzzProgram,
            f_name: &str,
            index: usize,
            depth: usize,
        ) -> Result<()> {
            log!(
                trace,
                "select node and parents for {index}-th arg of {f_name}"
            );
            // select a node and then upwalk the API_TREE to collect all parents.
            let func_node = rand_choose_func_index_node(f_name, index);
            let parents = get_parent_nodes_recursively(func_node);
            if parents.is_empty() {
                log!(trace, "create this arg by rules.");
                self.set_ith_call_arg(program, index, depth)?;
                return Ok(());
            }
            _verbose_parents(&parents);

            // generate callstmt for each parent and save in a vector.
            let mut call_vector: Vec<(Option<CallStmt>, Option<usize>)> = Vec::new();
            for node in parents {
                let new_name = &node.borrow().func.func_name;
                if is_gadget_exist(new_name) {
                    let mut new_call =
                        CallStmt::generate_new(program, CallStmt::RELATIVE, new_name, depth + 1)?;
                    // set arg exact values
                    new_call.set_arg_values_by_slice(program, node.clone())?;
                    call_vector.push((Some(new_call), node.borrow().index));
                } else {
                    call_vector.push((None, None));
                }
            }
            // the first call produces the argment.
            let (producer_call, _) = call_vector.pop().unwrap();
            let type_name = self.fg.arg_types[index];
            let arg_ident = self.fg.arg_idents[index];
            let producer_index: StmtIndex;
            if let Some(producer_call) = producer_call {
                crate::log!(
                    trace,
                    "use call `{}` to produce the arg ",
                    producer_call.fg.f_name
                );
                let mut producer_call = producer_call;
                producer_call.ident = arg_ident.to_string();
                let _tmp = crate::ReuseStmtGuard::temp_disable();
                let call_index = program.insert_or_append_stmt(producer_call)?;
                let _ = program
                    .insert_or_append_stmt(AssertStmt::assert_non_null(call_index.use_index()));
                let mut ptr_load = LoadStmt::generate_null(type_name, arg_ident)?;
                let mut loc = Location::stmt(call_index);
                loc.fields.push(FieldKey::Pointer);
                ptr_load.state.get_pointer_mut()?.pointer_location = loc;
                producer_index = program.insert_or_append_stmt(ptr_load)?;
            } else {
                self.set_ith_call_arg(program, index, depth)?;
                producer_index = self.args[index].use_index();
            }

            // insert the rest relative call into program.
            while !call_vector.is_empty() {
                let (relative_call, relative_index) = call_vector.pop().unwrap();
                if relative_call.is_none() {
                    continue;
                }
                let mut relative_call = relative_call.unwrap();
                log!(
                    trace,
                    "insert relative call `{}` in slice",
                    relative_call.fg.f_name
                );
                if relative_index.is_none() {
                    return Err(eyre::eyre!(
                        "Invalid relateive_index `{}`-ith of `{}`",
                        "None",
                        relative_call.fg.f_name
                    ));
                }
                relative_call.set_ith_arg_for_relative_call(
                    program,
                    relative_index.unwrap(),
                    producer_index.clone(),
                    type_name,
                )?;
                let _ = program.insert_or_append_stmt(relative_call)?;
            }
            self.set_arg(index, producer_index);
            Ok(())
        }
    }
}
