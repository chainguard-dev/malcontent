import "elf"

rule single_load_rwe {
  meta:
    description = "Flags binaries with a single LOAD segment marked as RWE."
    family = "Stager"
    filetype = "ELF"
  condition:
    elf.number_of_segments == 1 and elf.segments[0].type == elf.PT_LOAD and elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address {
  meta:
    description = "A fake sections header has been added to the binary."
    family = "Obfuscation"
    filetype = "ELF"
  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_segments > 0 and elf.number_of_sections > 0 and not (for any i in (0..elf.number_of_segments) : ((elf.segments[i].offset <= elf.entry_point) and ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and for any j in (0..elf.number_of_sections) : (elf.sections[j].offset <= elf.entry_point and ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) == (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset)))))
}

rule fake_dynamic_symbols {
  meta:
    description = "A fake dynamic symbol table has been added to the binary"
    family = "Obfuscation"
    filetype = "ELF"
  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_sections > 0 and elf.dynamic_section_entries > 0 and for any i in (0..elf.dynamic_section_entries) : (elf.dynamic[i].type == elf.DT_SYMTAB and not (for any j in (0..elf.number_of_sections) : (elf.sections[j].type == elf.SHT_DYNSYM and for any k in (0..elf.number_of_segments) : ((elf.segments[k].virtual_address <= elf.dynamic[i].val) and ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset))))
}
