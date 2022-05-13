use arrayvec::ArrayString;

use crate::error::{InvalidImageReason::*, ReadImageError::*, ReadImageResult};
use crate::io::{r, ReadExt, SeekExt};
use std::io::{Read, Seek};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageHeader {
    pub coff: Coff,
    pub opt: Optional,
    pub dirs: [DataDirectory; 16],
    pub sections: Vec<Section>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coff {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Optional {
    // Optional Header Standard Fields
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,

    // Optional Header Windows-Specific Fields
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
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: SectionName,
    pub virtual_size: u32,
    pub virtual_addr: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SectionName(pub ArrayString<8>);

#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataDirectories {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Certificate = 4,
    BaseRelocation = 5,
    Debug = 6,
    Reserved1 = 7,
    GlobalPtr = 8,
    TLS = 9,
    LoadConfig = 10,
    BoundImport = 11,
    IAT = 12,
    DelayImportDescriptor = 13,
    ClrRuntimeHeader = 14,
    Reserved2 = 15,
}

impl ImageHeader {
    pub fn read(mut data: &mut (impl Read + Seek)) -> ReadImageResult<Self> {
        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
        // Fields are skipped if they are reserved, deprecated, or unerringly replaceable

        data.jump(0x3C)?;
        let mut offset: u16 = data.readv()?;
        offset += 4;
        data.goto(offset.into())?;

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
        };

        if opt.num_data_dirs != 16 {
            dbg!(opt.num_data_dirs);
            return Err(InvalidImage(DataDirectories(opt.num_data_dirs)));
        }

        let mut dirs = [DataDirectory { rva: 0, size: 0 }; 16];
        for i in 0..16 {
            dirs[i] = data.readv()?;
        }

        let mut sections = Vec::with_capacity(coff.number_of_sections.into());
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
            dirs,
            sections,
        })
    }
}
