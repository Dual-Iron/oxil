use num_enum::TryFromPrimitive;

bitflags::bitflags! {
    pub struct AssemblyFlags: u32 {
        const PUBLIC_KEY = 0x1;
        const RETARGETABLE = 0x100;
        const DISABLE_JIT_COMPILE_OPTIMIZER = 0x4000;
        const ENABLE_JIT_COMPILE_TRACKING = 0x8000;
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive)]
pub enum AssemblyHashAlgorithm {
    None = 0,
    MD5 = 0x8003,
    SHA1 = 0x8004,
}
