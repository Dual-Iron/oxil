use arrayvec::ArrayString;

use crate::error::ReadImageError;
use crate::error::ReadImageResult;
use crate::read;
use std::io::{Read, Seek};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHeader {
    // COFF file header
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,

    // Optional Header Standard Fields
    pe64: bool,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,

    // Optional Header Windows-Specific Fields
    base_of_data: Option<u32>,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    size_of_image: u32,
    size_of_headers: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,

    // Optional Header Data Directories
    export: DataDirectory,
    import: DataDirectory,
    resource: DataDirectory,
    exception: DataDirectory,
    certificate: DataDirectory,
    base_relocation: DataDirectory,
    debug: DataDirectory,
    global_ptr: DataDirectory,
    tls: DataDirectory,
    load_config: DataDirectory,
    bound_import: DataDirectory,
    iat: DataDirectory,
    delay_import_descriptor: DataDirectory,
    clr_runtime_header: DataDirectory,

    // Section headers
    sections: Vec<SectionHeader>,
}

impl ImageHeader {
    pub fn read(mut data: &mut (impl Read + Seek)) -> ReadImageResult<Self> {
        // If any fields are skipped, it's because either:
        // - they are "reserved" by MSDN [https://docs.microsoft.com/en-us/windows/win32/debug/pe-format]
        // - replacing them with another value will never affect the resulting program

        read!(data for:
            // DOS header
            goto 0x3C,
            pe_signature_offset: u32,
            goto pe_signature_offset + 4,

            // COFF file header
            machine: u16,
            number_of_sections: u16,
            time_date_stamp: u32,
            pointer_to_symbol_table: u32,
            number_of_symbols: u32,
            size_of_optional_header: u16,
            characteristics: u16,

            // Optional Header Standard Fields
            magic: u16,
            major_linker_version: u8,
            minor_linker_version: u8,
            size_of_code: u32,
            size_of_initialized_data: u32,
            size_of_uninitialized_data: u32,
            address_of_entry_point: u32,
            base_of_code: u32,
        );

        if machine != 0x14C {
            return Err(ReadImageError::InvalidImage);
        }

        let pe64 = match magic {
            0x10B => false,
            0x20B => true,
            _ => return Err(ReadImageError::InvalidImage),
        };

        let base_of_data = if pe64 { None } else { Some(read! { data u32 }) };

        // Optional Header Windows-Specific Fields
        let image_base = match pe64 {
            true => read! { data u64 },
            false => (read! { data u32 }) as u64,
        };

        read!(data for:
            section_alignment: u32,
            file_alignment: u32,
            major_operating_system_version: u16,
            minor_operating_system_version: u16,
            major_image_version: u16,
            minor_image_version: u16,
            major_subsystem_version: u16,
            minor_subsystem_version: u16,
            skip 4,
            size_of_image: u32,
            size_of_headers: u32,
            skip 4, // ignore checksum
            subsystem: u16,
            dll_characteristics: u16,
        );

        let (
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
        ) = if pe64 {
            read! { data for: a: u64, b: u64, c: u64, d: u64, };
            (a, b, c, d)
        } else {
            read! { data for: a: u32, b: u32, c: u32, d: u32, };
            (a as u64, b as u64, c as u64, d as u64)
        };

        read!(data for:
            skip 4,
            number_of_rva_and_sizes: u32,

            // Optional Header Data Directories
            export: DataDirectory,
            import: DataDirectory,
            resource: DataDirectory,
            exception: DataDirectory,
            certificate: DataDirectory,
            base_relocation: DataDirectory,
            debug: DataDirectory,
            skip 8,
            global_ptr: DataDirectory,
            tls: DataDirectory,
            load_config: DataDirectory,
            bound_import: DataDirectory,
            iat: DataDirectory,
            delay_import_descriptor: DataDirectory,
            clr_runtime_header: DataDirectory,
            skip 8,
        );

        if number_of_rva_and_sizes < 16 {
            return Err(ReadImageError::InvalidImage);
        }

        let mut sections = Vec::with_capacity(number_of_sections as usize);

        for _ in 0..number_of_sections {
            read!(data for:
                name: str8,
                virtual_size: u32,
                virtual_addr: u32,
                size_of_raw_data: u32,
                pointer_to_raw_data: u32,
                skip 12,
                characteristics: u32,
            );
            sections.push(SectionHeader {
                name,
                virtual_size,
                virtual_addr,
                size_of_raw_data,
                pointer_to_raw_data,
                characteristics,
            })
        }

        Ok(ImageHeader {
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
            pe64,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            base_of_data,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            size_of_image,
            size_of_headers,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            export,
            import,
            resource,
            exception,
            certificate,
            base_relocation,
            debug,
            global_ptr,
            tls,
            load_config,
            bound_import,
            iat,
            delay_import_descriptor,
            clr_runtime_header,
            sections,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DataDirectory {
    rva: u32,
    size: u32,
}

impl DataDirectory {
    fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self {
            rva: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            size: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    name: ArrayString<8>,
    virtual_size: u32,
    virtual_addr: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    #[test]
    fn it_works() -> std::io::Result<()> {
        let mut data = include_bytes!("../HelloWorld.dll").as_ref();
        let mut data = Cursor::new(&mut data);

        dbg!(super::ImageHeader::read(&mut data).expect("success"));

        Ok(())
    }
}
