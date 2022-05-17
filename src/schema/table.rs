use super::{index::*, parsing::*, values::*, *};

macro_rules! tables {
    ( $($name:ident ( $($fname:ident: $ftype:ty),* ) )+ ) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            $(pub $fname: $ftype),*
        }

        impl Table for $name {
            const INDEX: TableIndex = TableIndex::$name;
            fn row_size(db: DbMeta<'_>) -> u8 {
                // Sum the fields' sizes.
                0 $(+ <$ftype as DbRead>::size(db))*
            }
            fn row(db: DbMeta<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
                // Read each field.
                Ok(Self {
                    $($fname: <$ftype as DbRead>::read(db, data)?,)*
                })
            }
        })+
    };
}

tables! {
Module(generation: u16, name: StringIndex, mvid: GuidIndex, enc_id: GuidIndex, enc_base_id: GuidIndex)
TypeRef(resolution_scope: ResolutionScope, type_name: StringIndex, type_namespace: StringIndex)
Assembly(
    hash_alg_id: AssemblyHashAlgorithm,
    major_version: u16,
    minor_version: u16,
    build_number: u16,
    revision_number: u16,
    flags: AssemblyFlags,
    public_key: BlobIndex,
    name: StringIndex,
    culture: StringIndex
)
AssemblyOs(os_platform_id: u32, os_major_version: u32, os_minor_version: u32)
AssemblyProcessor(processor: u32)
}
