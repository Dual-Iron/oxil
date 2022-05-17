use crate::{
    error::{ReadImageError::*, ReadImageResult},
    mod_read, ModuleRead,
};
use arrayvec::{ArrayString, ArrayVec};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ImageHeader {
    pub coff: Coff,
    pub opt: Optional,
    pub sections: ArrayVec<Section, 16>, // non-copy for some silly reason
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Coff {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Optional {
    // Standard Fields
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,

    // Windows-Specific Fields
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub num_data_dirs: u32,

    // Data Directories
    pub export: DataDirectory,
    pub import: DataDirectory,
    pub resource: DataDirectory,
    pub exception: DataDirectory,
    pub certificate: DataDirectory,
    pub base_relocation: DataDirectory,
    pub debug: DataDirectory,
    pub global_ptr: DataDirectory,
    pub tls: DataDirectory,
    pub load_config: DataDirectory,
    pub bound_import: DataDirectory,
    pub iat: DataDirectory,
    pub delay_import_descriptor: DataDirectory,
    pub clr_runtime_header: DataDirectory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Section {
    pub name: ArrayString<8>,
    pub virtual_size: u32,
    pub virtual_addr: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

pub fn section_from(sections: &[Section], rva: u32) -> Option<&Section> {
    sections
        .iter()
        .find(|s| rva >= s.virtual_addr && rva < s.virtual_addr + s.virtual_size)
}

pub fn offset_from(sections: &[Section], rva: u32) -> Option<u32> {
    section_from(sections, rva).map(|s| rva - s.virtual_addr + s.pointer_to_raw_data)
}

impl ImageHeader {
    pub fn read(data: &mut impl ModuleRead) -> ReadImageResult<Self> {
        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
        // Fields are skipped if they are reserved, deprecated, or unerringly replaceable

        data.skip(0x3C)?;
        let goto = data.u16()?;
        data.goto(goto.into())?;

        let pe_signature = data.read_bytes()?;
        if &pe_signature != b"PE\0\0" {
            return Err(PeSignature(pe_signature));
        }

        let coff = Coff {
            machine: data.u16()?,
            number_of_sections: data.u16()?,
            time_date_stamp: data.u32()?,
            pointer_to_symbol_table: data.u32()?,
            number_of_symbols: data.u32()?,
            size_of_optional_header: data.u16()?,
            characteristics: data.u16()?,
        };

        let pe64 = match data.u16()? {
            0x10B => false,
            0x20B => true,
            magic => return Err(Magic(magic)),
        };

        let opt = Optional {
            major_linker_version: data.u8()?,
            minor_linker_version: data.u8()?,
            size_of_code: data.u32()?,
            size_of_initialized_data: data.u32()?,
            size_of_uninitialized_data: data.u32()?,
            address_of_entry_point: data.u32()?,
            base_of_code: data.u32()?,
            base_of_data: if pe64 { None } else { Some(data.u32()?) },

            image_base: mod_read!(fit data to pe64),
            section_alignment: data.u32()?,
            file_alignment: data.u32()?,
            major_operating_system_version: data.u16()?,
            minor_operating_system_version: data.u16()?,
            major_image_version: data.u16()?,
            minor_image_version: data.u16()?,
            major_subsystem_version: data.u16()?,
            minor_subsystem_version: mod_read!(eval data.u16()?, then data.skip(4)?), // skip Win32VersionValue, must be zero
            size_of_image: data.u32()?,
            size_of_headers: mod_read!(eval data.u32()?, then data.skip(4)?), // skip CheckSum, I don't know what to do with it anyway
            subsystem: data.u16()?,
            dll_characteristics: data.u16()?,
            size_of_stack_reserve: mod_read!(fit data to pe64),
            size_of_stack_commit: mod_read!(fit data to pe64),
            size_of_heap_reserve: mod_read!(fit data to pe64),
            size_of_heap_commit: mod_read!(eval mod_read!(fit data to pe64), then data.skip(4)?), // skip LoaderFlags, must be zero
            num_data_dirs: data.u32()?,

            export: data.data_dir()?,
            import: data.data_dir()?,
            resource: data.data_dir()?,
            exception: data.data_dir()?,
            certificate: data.data_dir()?,
            base_relocation: data.data_dir()?,
            debug: mod_read!(eval data.data_dir()?, then data.skip(8)?), // skip Architecture, must be zero
            global_ptr: data.data_dir()?,
            tls: data.data_dir()?,
            load_config: data.data_dir()?,
            bound_import: data.data_dir()?,
            iat: data.data_dir()?,
            delay_import_descriptor: data.data_dir()?,
            clr_runtime_header: mod_read!(eval data.data_dir()?, then data.skip(8)?), // skip Reserved, must be zero
        };

        if opt.num_data_dirs != 16 {
            return Err(DataDirectories(opt.num_data_dirs));
        }

        if coff.number_of_sections > 16 {
            return Err(SectionCount(coff.number_of_sections));
        }

        let mut sections = ArrayVec::new();
        for _ in 0..coff.number_of_sections {
            sections.push(Section {
                name: data.section_name()?,
                virtual_size: data.u32()?,
                virtual_addr: data.u32()?,
                size_of_raw_data: data.u32()?,
                pointer_to_raw_data: mod_read!(eval data.u32()?, then data.skip(12)?),
                characteristics: data.u32()?,
            });
        }

        Ok(Self {
            coff,
            opt,
            sections,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_header() {
        let image = ImageHeader::read(&mut crate::hello_world_test()).expect("image header");

        assert_eq!(image, hello_world_header());
    }

    fn hello_world_header() -> ImageHeader {
        ImageHeader {
            coff: Coff {
                machine: 0x14C,
                number_of_sections: 3,
                time_date_stamp: 3028023590,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 224,
                characteristics: 34,
            },
            opt: Optional {
                major_linker_version: 48,
                minor_linker_version: 0,
                size_of_code: 0x800,
                size_of_initialized_data: 0x800,
                size_of_uninitialized_data: 0,
                address_of_entry_point: 9810,
                base_of_code: 0x2000,
                base_of_data: Some(0x4000),
                image_base: 0x400000,
                section_alignment: 0x2000,
                file_alignment: 0x200,
                major_operating_system_version: 4,
                minor_operating_system_version: 0,
                major_image_version: 0,
                minor_image_version: 0,
                major_subsystem_version: 4,
                minor_subsystem_version: 0,
                size_of_image: 0x8000,
                size_of_headers: 0x200,
                subsystem: 3,
                dll_characteristics: 34144,
                size_of_stack_reserve: 0x100000,
                size_of_stack_commit: 0x1000,
                size_of_heap_reserve: 0x100000,
                size_of_heap_commit: 0x1000,
                num_data_dirs: 16,
                export: DataDirectory { rva: 0, size: 0 },
                import: DataDirectory {
                    rva: 0x25FD,
                    size: 0x4F,
                },
                resource: DataDirectory {
                    rva: 0x4000,
                    size: 0x564,
                },
                exception: DataDirectory { rva: 0, size: 0 },
                certificate: DataDirectory { rva: 0, size: 0 },
                base_relocation: DataDirectory {
                    rva: 0x6000,
                    size: 0xC,
                },
                debug: DataDirectory {
                    rva: 0x2528,
                    size: 0x54,
                },
                global_ptr: DataDirectory { rva: 0, size: 0 },
                tls: DataDirectory { rva: 0, size: 0 },
                load_config: DataDirectory { rva: 0, size: 0 },
                bound_import: DataDirectory { rva: 0, size: 0 },
                iat: DataDirectory {
                    rva: 0x2000,
                    size: 0x8,
                },
                delay_import_descriptor: DataDirectory { rva: 0, size: 0 },
                clr_runtime_header: DataDirectory {
                    rva: 0x2008,
                    size: 0x48,
                },
            },
            sections: [
                Section {
                    name: ".text\u{0}\u{0}\u{0}".try_into().unwrap(),
                    virtual_size: 1624,
                    virtual_addr: 8192,
                    size_of_raw_data: 2048,
                    pointer_to_raw_data: 512,
                    characteristics: 1610612768,
                },
                Section {
                    name: ".rsrc\u{0}\u{0}\u{0}".try_into().unwrap(),
                    virtual_size: 1380,
                    virtual_addr: 16384,
                    size_of_raw_data: 1536,
                    pointer_to_raw_data: 2560,
                    characteristics: 1073741888,
                },
                Section {
                    name: ".reloc\u{0}\u{0}".try_into().unwrap(),
                    virtual_size: 12,
                    virtual_addr: 24576,
                    size_of_raw_data: 512,
                    pointer_to_raw_data: 4096,
                    characteristics: 1107296320,
                },
            ]
            .into_iter()
            .collect(),
        }
    }
}
