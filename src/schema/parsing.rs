use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DbMeta<'a> {
    pub lstreams: u8,
    pub rows: &'a [u32],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive)]
pub enum TableIndex {
    Assembly = 0x20,
    AssemblyOs = 0x22,
    AssemblyProcessor = 0x21,
    AssemblyRef = 0x23,
    AssemblyRefOs = 0x25,
    AssemblyRefProcessor = 0x24,
    ClassLayout = 0xF,
    Constant = 0xB,
    CustomAttribute = 0xC,
    DeclSecurity = 0xE,
    EventMap = 0x12,
    Event = 0x14,
    ExportedType = 0x27,
    Field = 0x4,
    FieldLayout = 0x10,
    FieldMarshal = 0xD,
    FieldRva = 0x1D,
    File = 0x26,
    GenericParam = 0x2A,
    GenericParamConstraint = 0x2C,
    ImplMap = 0x1C,
    InterfaceImpl = 0x9,
    ManifestResource = 0x28,
    MemberRef = 0xA,
    MethodDef = 0x6,
    MethodImpl = 0x19,
    MethodSemantics = 0x18,
    MethodSpec = 0x2B,
    Module = 0,
    ModuleRef = 0x1A,
    NestedClass = 0x29,
    Param = 0x8,
    Property = 0x17,
    PropertyMap = 0x15,
    StandAloneSig = 0x11,
    TypeDef = 0x2,
    TypeRef = 0x1,
    TypeSpec = 0x1B,
}

pub trait Table: Sized {
    const INDEX: TableIndex;
    fn row_size(db: DbMeta<'_>) -> u8;
    fn row(db: DbMeta<'_>, data: &mut impl ModuleRead) -> ReadImageResult<Self>;
}
