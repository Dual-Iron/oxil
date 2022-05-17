use crate::{
    error::{InvalidImageReason::*, ReadImageError::*, ReadImageResult},
    io::{r, ReadBytes, ReadExt, SeekExt},
};
use arrayvec::{ArrayString, ArrayVec};
use std::io::{BufRead, Seek};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ImageHeader {
    pub coff: Coff,
    pub opt: Optional,
    pub sections: ArrayVec<Section, 16>,
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
    pub name: SectionName,
    pub virtual_size: u32,
    pub virtual_addr: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SectionName(pub ArrayString<8>);

pub fn section_from(sections: &[Section], rva: u32) -> Option<&Section> {
    sections
        .iter()
        .find(|s| rva >= s.virtual_addr && rva < s.virtual_addr + s.virtual_size)
}

pub fn offset_from(sections: &[Section], rva: u32) -> Option<u32> {
    section_from(sections, rva).map(|s| rva - s.virtual_addr + s.pointer_to_raw_data)
}

impl ImageHeader {
    pub fn read(mut data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
        // Fields are skipped if they are reserved, deprecated, or unerringly replaceable

        data.jump(0x3C)?;
        let offset: u16 = data.readv()?;
        data.goto(offset.into())?;

        let pe_signature = data.read_bytes()?;
        if &pe_signature != b"PE\0\0" {
            return Err(InvalidImage(PeSignature(pe_signature)));
        }

        let coff = Coff {
            machine: data.readv()?,
            number_of_sections: data.readv()?,
            time_date_stamp: data.readv()?,
            pointer_to_symbol_table: data.readv()?,
            number_of_symbols: data.readv()?,
            size_of_optional_header: data.readv()?,
            characteristics: data.readv()?,
        };

        let pe64 = match data.readv()? {
            0x10B_u16 => false,
            0x20B => true,
            magic => return Err(InvalidImage(Magic(magic))),
        };

        let opt = Optional {
            major_linker_version: data.readv()?,
            minor_linker_version: data.readv()?,
            size_of_code: data.readv()?,
            size_of_initialized_data: data.readv()?,
            size_of_uninitialized_data: data.readv()?,
            address_of_entry_point: data.readv()?,
            base_of_code: data.readv()?,
            base_of_data: if pe64 { None } else { Some(data.readv()?) },

            image_base: r!(data: if pe64 => u64 | u32),
            section_alignment: data.readv()?,
            file_alignment: data.readv()?,
            major_operating_system_version: data.readv()?,
            minor_operating_system_version: data.readv()?,
            major_image_version: data.readv()?,
            minor_image_version: data.readv()?,
            major_subsystem_version: data.readv()?,
            minor_subsystem_version: r!(eval data.readv()?, then data.jump(4)?), // skip Win32VersionValue, must be zero
            size_of_image: data.readv()?,
            size_of_headers: r!(eval data.readv()?, then data.jump(4)?), // skip CheckSum, I don't know what to do with it anyway
            subsystem: data.readv()?,
            dll_characteristics: data.readv()?,
            size_of_stack_reserve: r!(data: if pe64 => u64 | u32),
            size_of_stack_commit: r!(data: if pe64 => u64 | u32),
            size_of_heap_reserve: r!(data: if pe64 => u64 | u32),
            size_of_heap_commit: r!(eval r!(data: if pe64 => u64 | u32), then data.jump(4)?), // skip LoaderFlags, must be zero
            num_data_dirs: data.readv()?,

            export: data.readv()?,
            import: data.readv()?,
            resource: data.readv()?,
            exception: data.readv()?,
            certificate: data.readv()?,
            base_relocation: data.readv()?,
            debug: r!(eval data.readv()?, then data.jump(8)?), // skip Architecture, must be zero
            global_ptr: data.readv()?,
            tls: data.readv()?,
            load_config: data.readv()?,
            bound_import: data.readv()?,
            iat: data.readv()?,
            delay_import_descriptor: data.readv()?,
            clr_runtime_header: r!(eval data.readv()?, then data.jump(8)?), // skip Reserved, must be zero
        };

        if opt.num_data_dirs != 16 {
            return Err(InvalidImage(DataDirectories(opt.num_data_dirs)));
        }

        if coff.number_of_sections > 16 {
            return Err(InvalidImage(SectionCount(coff.number_of_sections)));
        }

        let mut sections = ArrayVec::new();
        for _ in 0..coff.number_of_sections {
            sections.push(Section {
                name: data.readv()?,
                virtual_size: data.readv()?,
                virtual_addr: data.readv()?,
                size_of_raw_data: data.readv()?,
                pointer_to_raw_data: r!(eval data.readv()?, then data.jump(12)?),
                characteristics: data.readv()?,
            });
        }

        Ok(Self {
            coff,
            opt,
            sections,
        })
    }
}
