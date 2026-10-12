#[path = "../ebpf_validation.rs"]
mod ebpf_validation;

use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

fn object_with_memory_function(name: &str, called: bool) -> Vec<u8> {
    let mut object = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
    let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    // A memory fallback may be exported but unused; only references are rejected.
    object.append_section_data(text, &[0x95, 0, 0, 0, 0, 0, 0, 0], 8);
    let memory = object.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 8,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let xdp = object.add_section(Vec::new(), b"xdp".to_vec(), SectionKind::Text);
    let mut body = vec![0x85, 0, 0, 0, 188, 0, 0, 0];
    if called {
        body.extend_from_slice(&[0x85, 0x10, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    }
    body.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    object.append_section_data(xdp, &body, 8);
    object.add_symbol(Symbol {
        name: b"ingress".to_vec(),
        value: 0,
        size: body.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(xdp),
        flags: SymbolFlags::None,
    });
    if called {
        object
            .add_relocation(
                xdp,
                Relocation {
                    offset: 8,
                    symbol: memory,
                    addend: 0,
                    flags: object::RelocationFlags::Elf {
                        r_type: object::elf::R_BPF_64_32,
                    },
                },
            )
            .unwrap();
    }
    object.write().unwrap()
}

#[test]
fn rejects_memory_calls_but_allows_unused_fallbacks() {
    for name in ["memset", "memcpy", "memmove", "memcmp", "bcmp"] {
        ebpf_validation::validate(&object_with_memory_function(name, false)).unwrap();
        let error =
            ebpf_validation::validate(&object_with_memory_function(name, true)).unwrap_err();
        assert!(error.contains(&format!("calls {name}")), "{error}");
    }
}
