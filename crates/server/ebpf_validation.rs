use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

/// Catch compiler-generated panic paths, memory calls and malformed function
/// endings before embedding an object. This does not replace the kernel verifier.
pub fn validate(bytes: &[u8]) -> Result<(), String> {
    let file = object::File::parse(bytes).map_err(|e| format!("invalid eBPF object: {e}"))?;
    if file.format() != object::BinaryFormat::Elf
        || file.architecture() != object::Architecture::Bpf
    {
        return Err("expected an eBPF ELF object".into());
    }
    for section in file.sections() {
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        for (_, relocation) in section.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let symbol = file.symbol_by_index(index).map_err(|e| e.to_string())?;
            let name = symbol.name().map_err(|e| e.to_string())?;
            if matches!(name, "memset" | "memcpy" | "memmove" | "memcmp" | "bcmp") {
                return Err(format!(
                    "eBPF object calls {name}; fixed-size memory operations must be expanded \
                     into loads/stores for restricted capabilities \
                     (build with --disable-expand-memcpy-in-order)"
                ));
            }
        }
    }
    let mut ingress = false;
    for symbol in file.symbols() {
        if symbol.kind() != object::SymbolKind::Text || !symbol.is_definition() {
            continue;
        }
        let name = symbol.name().map_err(|e| e.to_string())?;
        if name.contains("panic") || name.contains("rust_begin_unwind") {
            return Err(format!(
                "eBPF object contains panic function {name}; packet reads must be fallible"
            ));
        }
        let section = file
            .section_by_index(symbol.section_index().ok_or("function has no section")?)
            .map_err(|e| e.to_string())?;
        let start = symbol
            .address()
            .checked_sub(section.address())
            .and_then(|v| usize::try_from(v).ok())
            .ok_or("invalid function offset")?;
        let size = usize::try_from(symbol.size()).map_err(|e| e.to_string())?;
        let end = start.checked_add(size).ok_or("function size overflow")?;
        let body = section
            .data()
            .map_err(|e| e.to_string())?
            .get(start..end)
            .ok_or("function extends past section")?;
        if body.len() < 8 || body.len() % 8 != 0 {
            return Err(format!("invalid eBPF instruction length in {name}"));
        }
        // The supported generic BPF ISA requires a final EXIT or unconditional
        // JMP, including for subprograms appended by the loader.
        let opcode = body[body.len() - 8];
        if !matches!(opcode, 0x95 | 0x05) {
            return Err(format!(
                "eBPF function {name} ends with opcode {opcode:#04x}, not EXIT/JMP"
            ));
        }
        if name == "ingress" {
            ingress = section.name().map_err(|e| e.to_string())? == "xdp";
            // Length must come from helper 188 as a scalar, rather than
            // subtracting data/data_end pointers under the restricted caps.
            let scalar_length = body.chunks_exact(8).any(|insn| {
                let immediate: [u8; 4] = insn[4..8].try_into().unwrap();
                let helper = if file.is_little_endian() {
                    i32::from_le_bytes(immediate)
                } else {
                    i32::from_be_bytes(immediate)
                };
                insn[0] == 0x85 && insn[1] == 0 && helper == 188
            });
            if !scalar_length {
                return Err("ingress must obtain a scalar length from bpf_xdp_get_buff_len".into());
            }
        }
    }
    if !ingress {
        return Err("eBPF object is missing the ingress XDP function".into());
    }
    Ok(())
}
