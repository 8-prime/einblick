use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

// Einblick's ingress byte loads read either the stack (register 10) or packet
// data through XdpPacket::read_byte. Require the latter's fixed-width guard.
// This checks our emitted reader pattern, not general BPF pointer provenance.
fn validate_packet_reads(body: &[u8], little_endian: bool) -> Result<(), String> {
    let instructions: Vec<&[u8]> = body
        .as_chunks::<8>()
        .0
        .iter()
        .map(|i| i.as_slice())
        .collect();
    let dst = |i: &[u8]| if little_endian { i[1] & 15 } else { i[1] >> 4 };
    let src = |i: &[u8]| if little_endian { i[1] >> 4 } else { i[1] & 15 };
    let offset = |i: &[u8]| {
        let bytes = [i[2], i[3]];
        if little_endian {
            i16::from_le_bytes(bytes)
        } else {
            i16::from_be_bytes(bytes)
        }
    };
    let immediate = |i: &[u8]| {
        let bytes = i[4..8].try_into().unwrap();
        if little_endian {
            i32::from_le_bytes(bytes)
        } else {
            i32::from_be_bytes(bytes)
        }
    };
    for (index, load) in instructions.iter().enumerate() {
        if load[0] != 0x71 || src(load) == 10 {
            continue;
        }
        let guarded = index.checked_sub(2).is_some_and(|start| {
            let add = instructions[start];
            let check = instructions[start + 1];
            // pointer += 1; if pointer > data_end skip load; load [pointer - 1].
            offset(load) == -1
                && add[0] == 0x07
                && dst(add) == src(load)
                && immediate(add) == 1
                && check[0] == 0x2d
                && dst(check) == src(load)
                && offset(check) == 1
                && src(check) != src(load)
        });
        if !guarded {
            return Err(format!(
                "ingress byte load at instruction {index} lacks a fixed one-byte packet guard; \
                 check pointer + 1 > data_end before loading pointer - 1"
            ));
        }
    }
    Ok(())
}

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
            let scalar_length = body.as_chunks::<8>().0.iter().any(|insn| {
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
            validate_packet_reads(body, file.is_little_endian())?;
        }
    }
    if !ingress {
        return Err("eBPF object is missing the ingress XDP function".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_packet_reads;

    fn instruction(opcode: u8, dst: u8, src: u8, offset: i16, immediate: i32, le: bool) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[0] = opcode;
        bytes[1] = if le { dst | src << 4 } else { dst << 4 | src };
        bytes[2..4].copy_from_slice(&if le {
            offset.to_le_bytes()
        } else {
            offset.to_be_bytes()
        });
        bytes[4..8].copy_from_slice(&if le {
            immediate.to_le_bytes()
        } else {
            immediate.to_be_bytes()
        });
        bytes
    }

    #[test]
    fn rejects_zero_range_packet_guard() {
        for le in [true, false] {
            let body = [
                instruction(0x0f, 0, 2, 0, 0, le), // pointer += variable offset
                instruction(0x3d, 0, 1, 1, 0, le), // pointer >= end (old guard)
                instruction(0x71, 5, 0, 0, 0, le), // byte load at fixed offset zero
            ]
            .concat();
            assert!(
                validate_packet_reads(&body, le)
                    .unwrap_err()
                    .contains("one-byte packet guard")
            );
        }
    }

    #[test]
    fn requires_matching_pointer_width_and_branch() {
        for le in [true, false] {
            let body = [
                instruction(0x0f, 0, 2, 0, 0, le),
                instruction(0x07, 0, 0, 0, 1, le),
                instruction(0x2d, 0, 1, 1, 0, le),
                instruction(0x71, 5, 0, -1, 0, le),
            ]
            .concat();
            validate_packet_reads(&body, le).unwrap();
            for (position, replacement) in [
                (8, instruction(0x07, 0, 0, 0, 0, le)), // no positive fixed offset
                (16, instruction(0x2d, 2, 1, 1, 0, le)), // different checked pointer
                (16, instruction(0x2d, 0, 1, 0, 0, le)), // failure still executes load
                (24, instruction(0x71, 5, 0, 0, 0, le)), // load beyond proved range
            ] {
                let mut changed = body.clone();
                changed[position..position + 8].copy_from_slice(&replacement);
                assert!(validate_packet_reads(&changed, le).is_err());
            }
        }
    }
}
