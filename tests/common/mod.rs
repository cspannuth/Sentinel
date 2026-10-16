// Benign synthetic PE layout. These bytes are never loaded or executed.
pub fn pe_file(is_64: bool, imports: bool) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x600];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80); // e_lfanew
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, if is_64 { 0x8664 } else { 0x14c });
    put_u16(&mut bytes, 0x86, 1); // NumberOfSections
    put_u32(&mut bytes, 0x88, 1_700_000_000);
    let optional_size = if is_64 { 240 } else { 224 };
    put_u16(&mut bytes, 0x94, optional_size);
    put_u16(&mut bytes, 0x96, 0x2022); // Executable, large-address-aware, DLL
    let optional = 0x98;
    put_u16(&mut bytes, optional, if is_64 { 0x20b } else { 0x10b });
    put_u32(&mut bytes, optional + 16, 0x1000); // AddressOfEntryPoint
    put_u32(&mut bytes, optional + 20, 0x1000); // BaseOfCode
    if is_64 {
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    } else {
        put_u32(&mut bytes, optional + 24, 0x1000); // BaseOfData
        put_u32(&mut bytes, optional + 28, 0x40_0000);
    }
    put_u32(&mut bytes, optional + 32, 0x1000); // SectionAlignment
    put_u32(&mut bytes, optional + 36, 0x200); // FileAlignment
    put_u32(&mut bytes, optional + 56, 0x2000); // SizeOfImage
    put_u32(&mut bytes, optional + 60, 0x200); // SizeOfHeaders
    put_u16(&mut bytes, optional + 68, 3); // Console subsystem
    put_u16(&mut bytes, optional + 70, 0x140);
    let directories = optional + if is_64 { 112 } else { 96 };
    put_u32(&mut bytes, directories - 4, 16);

    let section = optional + optional_size as usize;
    bytes[section..section + 8].copy_from_slice(b".text\0\0\0");
    put_u32(&mut bytes, section + 8, 0x400);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x400);
    put_u32(&mut bytes, section + 20, 0x200);
    put_u32(&mut bytes, section + 36, 0x6000_0020); // Read + execute + code
    bytes[0x200..].fill(0x90);

    if imports {
        put_u32(&mut bytes, directories + 8, 0x1100);
        put_u32(&mut bytes, directories + 12, 40); // Descriptor + null descriptor
        bytes[0x300..0x328].fill(0);
        put_u32(&mut bytes, 0x300, 0x1180); // Lookup RVA
        put_u32(&mut bytes, 0x30c, 0x1160); // DLL name RVA
        put_u32(&mut bytes, 0x310, 0x11b0); // IAT RVA
        bytes[0x360..0x36d].copy_from_slice(b"KERNEL32.dll\0");
        bytes[0x380..0x398].fill(0);
        bytes[0x3b0..0x3c8].fill(0);
        if is_64 {
            bytes[0x380..0x388].copy_from_slice(&0x11e0_u64.to_le_bytes());
            bytes[0x388..0x390].copy_from_slice(&0x8000_0000_0000_002a_u64.to_le_bytes());
        } else {
            put_u32(&mut bytes, 0x380, 0x11e0);
            put_u32(&mut bytes, 0x384, 0x8000_002a);
        }
        bytes.copy_within(0x380..0x398, 0x3b0);
        put_u16(&mut bytes, 0x3e0, 7); // Name hint is not an ordinal
        bytes[0x3e2..0x3ee].copy_from_slice(b"ExitProcess\0");
    }
    bytes
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
