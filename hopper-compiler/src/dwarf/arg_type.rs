
#[derive(Debug, Clone)]
pub enum ArgType {
    Char(CharType),
    Integer(IntegerType),
    Void,
    TypeDef(DefType),
    Point(PointType),
    Const(ConstType),
    Struct(StructType),
    Array(ArrayType),
    Decla(DeclaType),
    Ref(RefType),
    Undefined,
}

#[derive(Debug, Clone)]
pub struct IntegerType {
    pub sign: bool,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct CharType {
    pub sign: bool,
}

#[derive(Debug, Clone)]
pub struct DefType {
    pub name: String,
    pub alias: Box<ArgType>,
}

#[derive(Debug, Clone)]
pub struct PointType {
    pub dst_type: Box<ArgType>,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct ConstType {
    pub inner_type: Box<ArgType>,
}

#[derive(Debug, Clone)]
pub struct StructType {
    pub name: String,
    pub fields: Vec<StructField>,
    pub size: usize,
    // position
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub ty: Box<ArgType>,
    pub location: usize,
}

#[derive(Debug, Clone)]
pub struct ArrayType {
    pub ele_type: Box<ArgType>,
    pub sub_range: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct DeclaType {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct RefType {
    pub offset: u64,
}

impl ArgType {
    pub fn from(name: &str, size: usize) -> Self {
        match name {
            "void" => ArgType::Void,
            "short int" | "int" | "long int" => ArgType::Integer(IntegerType { sign: true, size }),
            "short unsigned int" | "unsigned int" | "long unsigned int" => {
                ArgType::Integer(IntegerType { sign: false, size })
            }
            // FIXME: should make sure char signed or unsigned
            "char" | "signed char" => ArgType::Char(CharType { sign: true }),
            "unsigned char" => ArgType::Char(CharType { sign: false }),
            _ => {
                println!("name: {name}, size: {size}");
                ArgType::Undefined
            }
        }
    }

    pub fn alias(name: &str, alias_type: ArgType) -> Self {
        ArgType::TypeDef(DefType {
            name: name.to_string(),
            alias: Box::new(alias_type),
        })
    }

    pub fn pointer(dst_type: ArgType, size: usize) -> Self {
        ArgType::Point(PointType {
            dst_type: Box::new(dst_type),
            size,
        })
    }

    pub fn constt(inner_type: ArgType) -> Self {
        ArgType::Const(ConstType {
            inner_type: Box::new(inner_type),
        })
    }

    pub fn structt(name: &str, size: usize) -> Self {
        ArgType::Struct(StructType {
            name: name.to_string(),
            size,
            fields: vec![],
        })
    }

    pub fn array(ele_type: ArgType) -> Self {
        ArgType::Array(ArrayType {
            ele_type: Box::new(ele_type),
            sub_range: vec![],
        })
    }

    pub fn ref_as(offset: u64) -> Self {
        ArgType::Ref(RefType { offset })
    }

    /*
    use std::collections::BTreeMap;
    pub fn expand_ref<'a>(&'a self, type_table: &'a BTreeMap<u64, ArgType>) -> &'a ArgType {
        match self {
            ArgType::Ref(t) => t.find(type_table).unwrap_or_else(|| &ArgType::Undefined),
            _ => self,
        }
    } 
    */
}

/*
impl RefType {
    pub fn find<'a>(&self, type_table: &'a BTreeMap<u64, ArgType>) -> Option<&'a ArgType> {
        if let Some(r) = type_table.get(&self.offset) {
            Some(r)
        } else {
            None
        }
    }
} */
