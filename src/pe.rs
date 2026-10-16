//! Bounded, on-disk PE inspection. No code is loaded or executed.

use std::time::{Duration, Instant};

use goblin::pe::{
    header::CoffHeader, optional_header::OptionalHeader, section_table::SectionTable,
};
use scroll::Pread;
use serde::Serialize;

pub const MAX_PE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SECTIONS: usize = 256;
const MAX_IMPORTS: usize = 16_384;
const MAX_LIBRARIES: usize = 256;
const MAX_NAME_BYTES: usize = 1024;
const MAX_ENTROPY_BYTES: usize = 128 * 1024 * 1024;
const ANALYSIS_BUDGET: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PeOutcome {
    NotPe,
    Analyzed { report: Box<PeReport> },
    Skipped { reason: PeLimit, limit: u64 },
    Failed { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeLimit {
    InputBytes,
    Sections,
    Imports,
    Libraries,
    NameBytes,
    EntropyBytes,
    AnalysisMilliseconds,
}

#[derive(Debug, Serialize)]
pub struct PeReport {
    pub format: PeFormat,
    pub machine: u16,
    pub architecture: String,
    pub is_dll: bool,
    pub coff_timestamp: u32,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub sections: Vec<PeSection>,
    /// Normal import directory only; not delayed imports or runtime API resolution.
    pub imports: Vec<PeLibrary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeFormat {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Serialize)]
pub struct PeSection {
    pub name: String,
    pub name_bytes: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Entropy of exactly the raw on-disk bytes, including file padding; empty = 0.
    pub entropy: f64,
}

#[derive(Debug, Serialize)]
pub struct PeLibrary {
    pub dll: String,
    pub symbols: Vec<PeImport>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeImport {
    Name { name: String, hint: u16 },
    Ordinal { ordinal: u16 },
}

type AnalysisResult<T> = Result<T, PeOutcome>;

pub(crate) fn analyze(bytes: &[u8]) -> PeOutcome {
    if !bytes.starts_with(b"MZ") {
        return PeOutcome::NotPe;
    }
    if bytes.len() as u64 > MAX_PE_BYTES {
        return limited(PeLimit::InputBytes, MAX_PE_BYTES);
    }
    match parse(bytes) {
        Ok(report) => PeOutcome::Analyzed {
            report: Box::new(report),
        },
        Err(error) => error,
    }
}

fn parse(bytes: &[u8]) -> AnalysisResult<PeReport> {
    let started = Instant::now();
    // Identify the signature first: Goblin's DosHeader::parse also requires a
    // PE signature, so using it here would reject recognizable NE/LE/LX files.
    range(bytes, 0, 64)?;
    let pe_offset = bytes
        .pread_with::<u32>(0x3c, scroll::LE)
        .map_err(malformed)? as usize;
    if pe_offset < 64 {
        return Err(malformed("PE header overlaps the DOS header"));
    }
    let signature = range(bytes, pe_offset, 4)?;
    if signature != b"PE\0\0" {
        // A DOS executable may instead contain a legacy NE/LE/LX header.
        if matches!(&signature[..2], b"NE" | b"LE" | b"LX") {
            return Err(PeOutcome::NotPe);
        }
        return Err(malformed(
            "MZ candidate has no PE signature at its declared offset",
        ));
    }
    let mut offset = pe_offset + 4;
    let coff = CoffHeader::parse(bytes, &mut offset).map_err(malformed)?;
    let optional_bytes = range(bytes, offset, coff.size_of_optional_header as usize)?;
    // Parse only the declared optional header: do not borrow section bytes to fill missing fields.
    let optional: OptionalHeader = optional_bytes.pread(0).map_err(malformed)?;
    let format = match optional.standard_fields.magic {
        0x10b => PeFormat::Pe32,
        0x20b => PeFormat::Pe32Plus,
        _ => {
            return Err(malformed(
                "Only PE32 and PE32+ optional headers are supported",
            ));
        }
    };
    let section_count = coff.number_of_sections as usize;
    if section_count > MAX_SECTIONS {
        return Err(limited(PeLimit::Sections, MAX_SECTIONS as u64));
    }
    offset += optional_bytes.len();
    range(bytes, offset, section_count * 40)?;

    // Bound indirect COFF section names before Goblin allocates their strings.
    let string_table = (coff.pointer_to_symbol_table as u64)
        .checked_add(coff.number_of_symbol_table as u64 * 18)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| malformed("COFF string table offset overflow"))?;
    for index in 0..section_count {
        let name = range(bytes, offset + index * 40, 8)?;
        let mut section = SectionTable::default();
        section.name.copy_from_slice(name);
        if let Some(index) = section.name_offset().map_err(malformed)? {
            let position = string_table
                .checked_add(index)
                .ok_or_else(|| malformed("Section name offset overflow"))?;
            bounded_string(
                bytes
                    .get(position..)
                    .ok_or_else(|| malformed("Section name lies outside the file"))?,
            )?;
        }
    }
    let raw_sections = coff.sections(bytes, &mut offset).map_err(malformed)?;
    let windows = optional.windows_fields;
    if windows.size_of_headers as usize > bytes.len() || (windows.size_of_headers as usize) < offset
    {
        return Err(malformed(
            "SizeOfHeaders does not cover the headers within the file",
        ));
    }
    let mut sections = Vec::with_capacity(section_count);
    let mut entropy_bytes = 0_usize;
    for section in &raw_sections {
        check_time(started)?;
        let raw_size = section.size_of_raw_data as usize;
        let data = if raw_size == 0 {
            &[][..]
        } else {
            range(bytes, section.pointer_to_raw_data as usize, raw_size)?
        };
        entropy_bytes += raw_size;
        if entropy_bytes > MAX_ENTROPY_BYTES {
            return Err(limited(PeLimit::EntropyBytes, MAX_ENTROPY_BYTES as u64));
        }
        let name_end = section.name.iter().position(|&byte| byte == 0).unwrap_or(8);
        let name = section
            .real_name
            .clone()
            .unwrap_or_else(|| String::from_utf8_lossy(&section.name[..name_end]).into_owned());
        sections.push(PeSection {
            name,
            name_bytes: section.name,
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            raw_offset: section.pointer_to_raw_data,
            raw_size: section.size_of_raw_data,
            characteristics: section.characteristics,
            readable: section.characteristics & 0x4000_0000 != 0,
            writable: section.characteristics & 0x8000_0000 != 0,
            executable: section.characteristics & 0x2000_0000 != 0,
            entropy: entropy(data, started)?,
        });
    }
    let imports = match optional.data_directories.get_import_table() {
        None => Vec::new(),
        Some(directory) => parse_imports(
            bytes,
            &raw_sections,
            windows.size_of_headers,
            directory.virtual_address,
            directory.size,
            format,
            started,
        )?,
    };
    check_time(started)?;
    Ok(PeReport {
        format,
        machine: coff.machine,
        architecture: architecture(coff.machine).into(),
        is_dll: coff.characteristics & 0x2000 != 0,
        coff_timestamp: coff.time_date_stamp,
        characteristics: coff.characteristics,
        subsystem: windows.subsystem,
        dll_characteristics: windows.dll_characteristics,
        entry_point_rva: optional.standard_fields.address_of_entry_point,
        image_base: windows.image_base,
        size_of_image: windows.size_of_image,
        size_of_headers: windows.size_of_headers,
        section_alignment: windows.section_alignment,
        file_alignment: windows.file_alignment,
        sections,
        imports,
    })
}

fn architecture(machine: u16) -> &'static str {
    match machine {
        0x14c => "x86",
        0x8664 => "x86_64",
        0xaa64 => "arm64",
        0x1c0 => "arm",
        0x1c4 => "arm_thumb2",
        _ => "unknown",
    }
}

/// Resolve RVAs only to physically present bytes, rejecting ambiguous overlapping mappings.
fn rva_data<'a>(
    bytes: &'a [u8],
    sections: &[SectionTable],
    headers: u32,
    rva: u32,
) -> AnalysisResult<&'a [u8]> {
    let mut mapped = if rva < headers {
        Some(range(bytes, rva as usize, (headers - rva) as usize)?)
    } else {
        None
    };
    for section in sections {
        let Some(relative) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        if relative >= section.size_of_raw_data {
            continue;
        }
        if mapped.is_some() {
            return Err(malformed("Import RVA maps to overlapping ranges"));
        }
        let position = section.pointer_to_raw_data as u64 + relative as u64;
        let position = usize::try_from(position).map_err(malformed)?;
        mapped = Some(range(
            bytes,
            position,
            (section.size_of_raw_data - relative) as usize,
        )?);
    }
    mapped.ok_or_else(|| malformed(format!("Import RVA {rva:#x} has no on-disk mapping")))
}

// Goblin handles fixed headers/sections. Imports are walked here so descriptor,
// symbol, string, and time limits apply before allocation or repeated work.
fn parse_imports(
    bytes: &[u8],
    sections: &[SectionTable],
    headers: u32,
    rva: u32,
    size: u32,
    format: PeFormat,
    started: Instant,
) -> AnalysisResult<Vec<PeLibrary>> {
    let mapped = rva_data(bytes, sections, headers, rva)?;
    let table = range(mapped, 0, size as usize)?;
    let mut libraries = Vec::new();
    let mut import_count = 0;
    for descriptor in table.as_chunks::<20>().0 {
        check_time(started)?;
        if descriptor.iter().all(|&byte| byte == 0) {
            return Ok(libraries);
        }
        if libraries.len() == MAX_LIBRARIES {
            return Err(limited(PeLimit::Libraries, MAX_LIBRARIES as u64));
        }
        let name_rva: u32 = descriptor.pread_with(12, scroll::LE).map_err(malformed)?;
        let address_rva: u32 = descriptor.pread_with(16, scroll::LE).map_err(malformed)?;
        let lookup_rva: u32 = descriptor.pread_with(0, scroll::LE).map_err(malformed)?;
        if name_rva == 0 || address_rva == 0 {
            return Err(malformed("Incomplete import descriptor"));
        }
        let dll = bounded_string(rva_data(bytes, sections, headers, name_rva)?)?;
        let lookup_rva = if lookup_rva == 0 {
            address_rva
        } else {
            lookup_rva
        };
        let lookup = rva_data(bytes, sections, headers, lookup_rva)?;
        let address = rva_data(bytes, sections, headers, address_rva)?;
        let width = if format == PeFormat::Pe32Plus { 8 } else { 4 };
        let ordinal_flag = if width == 8 { 1_u64 << 63 } else { 1_u64 << 31 };
        let mut symbols = Vec::new();
        let mut terminated = false;
        for (index, thunk) in lookup.chunks_exact(width).enumerate() {
            check_time(started)?;
            // Validate the corresponding IAT slot, including the terminating slot.
            range(address, index * width, width)?;
            let value = if width == 8 {
                thunk.pread_with::<u64>(0, scroll::LE).map_err(malformed)?
            } else {
                thunk.pread_with::<u32>(0, scroll::LE).map_err(malformed)? as u64
            };
            if value == 0 {
                terminated = true;
                break;
            }
            if import_count == MAX_IMPORTS {
                return Err(limited(PeLimit::Imports, MAX_IMPORTS as u64));
            }
            import_count += 1;
            let symbol = if value & ordinal_flag != 0 {
                if value & !(ordinal_flag | 0xffff) != 0 {
                    return Err(malformed("Invalid reserved bits in ordinal import"));
                }
                PeImport::Ordinal {
                    ordinal: value as u16,
                }
            } else {
                let name_rva = u32::try_from(value).map_err(malformed)?;
                let data = rva_data(bytes, sections, headers, name_rva)?;
                let hint = data.pread_with(0, scroll::LE).map_err(malformed)?;
                let name = bounded_string(
                    data.get(2..)
                        .ok_or_else(|| malformed("Missing import name"))?,
                )?;
                PeImport::Name { name, hint }
            };
            symbols.push(symbol);
        }
        if !terminated {
            return Err(malformed("Unterminated import lookup table"));
        }
        libraries.push(PeLibrary { dll, symbols });
    }
    Err(malformed(
        "Import directory has no complete null terminator within its declared size",
    ))
}

fn bounded_string(bytes: &[u8]) -> AnalysisResult<String> {
    let examined = &bytes[..bytes.len().min(MAX_NAME_BYTES + 1)];
    match examined.iter().position(|&byte| byte == 0) {
        Some(0) => Err(malformed("Empty PE name")),
        Some(end) => std::str::from_utf8(&examined[..end])
            .map(String::from)
            .map_err(malformed),
        None if bytes.len() > MAX_NAME_BYTES => {
            Err(limited(PeLimit::NameBytes, MAX_NAME_BYTES as u64))
        }
        None => Err(malformed("Unterminated PE name")),
    }
}

fn entropy(bytes: &[u8], started: Instant) -> AnalysisResult<f64> {
    if bytes.is_empty() {
        return Ok(0.0);
    }
    let mut counts = [0_usize; 256];
    for chunk in bytes.chunks(64 * 1024) {
        check_time(started)?;
        for &byte in chunk {
            counts[byte as usize] += 1;
        }
    }
    Ok(counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum())
}

fn range(bytes: &[u8], offset: usize, size: usize) -> AnalysisResult<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| malformed("PE range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| malformed("PE range extends beyond available bytes"))
}

fn check_time(started: Instant) -> AnalysisResult<()> {
    if started.elapsed() > ANALYSIS_BUDGET {
        Err(limited(
            PeLimit::AnalysisMilliseconds,
            ANALYSIS_BUDGET.as_millis() as u64,
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn limited(reason: PeLimit, limit: u64) -> PeOutcome {
    PeOutcome::Skipped { reason, limit }
}

fn malformed(message: impl std::fmt::Display) -> PeOutcome {
    PeOutcome::Failed {
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooperative_time_budget_and_name_limits_are_explicit() {
        let expired = Instant::now()
            .checked_sub(ANALYSIS_BUDGET + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            check_time(expired),
            Err(PeOutcome::Skipped {
                reason: PeLimit::AnalysisMilliseconds,
                limit: 5000
            })
        ));
        let name = vec![b'a'; MAX_NAME_BYTES + 1];
        assert!(matches!(
            bounded_string(&name),
            Err(PeOutcome::Skipped {
                reason: PeLimit::NameBytes,
                ..
            })
        ));
        assert!(matches!(
            bounded_string(b"unterminated"),
            Err(PeOutcome::Failed { .. })
        ));
    }

    #[test]
    fn repeated_import_descriptors_cannot_amplify_parsing_without_a_limit() {
        // All descriptors refer to the same tiny library/table. Each lookup has
        // enough symbols to hit the global cap before the descriptor cap.
        let headers = 100_000;
        let mut bytes = vec![0_u8; headers as usize];
        bytes[30_000..30_002].copy_from_slice(b"d\0");
        for thunk in bytes[40_000..40_000 + 100 * 4].as_chunks_mut::<4>().0 {
            thunk.copy_from_slice(&0x8000_0001_u32.to_le_bytes());
        }
        for descriptor in bytes[100..100 + 200 * 20].as_chunks_mut::<20>().0 {
            descriptor[..4].copy_from_slice(&40_000_u32.to_le_bytes());
            descriptor[12..16].copy_from_slice(&30_000_u32.to_le_bytes());
            descriptor[16..20].copy_from_slice(&40_000_u32.to_le_bytes());
        }
        let result = parse_imports(
            &bytes,
            &[],
            headers,
            100,
            200 * 20 + 20,
            PeFormat::Pe32,
            Instant::now(),
        );
        assert!(matches!(
            result,
            Err(PeOutcome::Skipped {
                reason: PeLimit::Imports,
                limit: 16_384
            })
        ));
    }
}
