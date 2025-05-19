import "elf"
import "math"

rule single_load_rwe: critical {
  meta:
    description = "Binary with a single LOAD segment marked RWE"
    family      = "Stager"
    filetypes   = "elf"

    author = "Tenable"

  condition:
    elf.number_of_segments == 1 and elf.segments[0].type == elf.PT_LOAD and elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address: critical {
  meta:
    description = "binary with fake sections header"
    family      = "Obfuscation"
    filetypes   = "elf"

    author = "Tenable"

  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_segments > 0 and elf.number_of_sections > 0 and not (for any i in (0..elf.number_of_segments): ((elf.segments[i].offset <= elf.entry_point) and ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and for any j in (0..elf.number_of_sections): (elf.sections[j].offset <= elf.entry_point and ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) == (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset)))))
}

rule fake_dynamic_symbols: critical {
  meta:
    description = "binary with fake dynamic symbol table"
    family      = "Obfuscation"
    filetypes   = "elf"
    author      = "Tenable"

  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_sections > 0 and elf.dynamic_section_entries > 0 and for any i in (0..elf.dynamic_section_entries): (elf.dynamic[i].type == elf.DT_SYMTAB and not (for any j in (0..elf.number_of_sections): (elf.sections[j].type == elf.SHT_DYNSYM and for any k in (0..elf.number_of_segments): ((elf.segments[k].virtual_address <= elf.dynamic[i].val) and ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset))))
}

rule high_entropy_header: high {
  meta:
    description = "high entropy ELF header (>7)"
    filetypes   = "elf"

  strings:
    $not_pyinst = "pyi-bootloader-ignore-signals"
    $not_go     = "syscall_linux.go"
    $not_go2    = "vdso_linux.go"
    $not_module = ".module_license" fullword

  condition:
    uint32(0) == 1179403647 and elf.type == elf.ET_EXEC and math.entropy(1200, 4096) > 7 and none of ($not*)
}
