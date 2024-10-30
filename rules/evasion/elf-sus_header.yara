import "elf"

rule single_load_rwe: critical {
  meta:
    description                          = "Binary with a single LOAD segment marked RWE"
    family                               = "Stager"
    filetype                             = "ELF"
    hash_2024_Downloads_690f             = "690f29dd425f7415ecb50986aa26750960c39a0ca8a02ddfd37ec4196993bd9e"
    hash_2023_Downloads_cd54             = "cd54a34dbd7d345a7fd7fd8744feb5c956825317e9225edb002c3258683947f1"
    hash_2023_Linux_Malware_Samples_16e0 = "16e09592a9e85cd67530ec365ac2c50e48e873335c1ad0f984e3daaefc8a57b5"
    author                               = "Tenable"

  condition:
    elf.number_of_segments == 1 and elf.segments[0].type == elf.PT_LOAD and elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address: critical {
  meta:
    description                          = "binary with fake sections header"
    family                               = "Obfuscation"
    filetype                             = "ELF"
    hash_2024_Downloads_e241             = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2023_Linux_Malware_Samples_19f7 = "19f76bf2be3ea11732f2c5c562afbd6f363b062c25fba3a143c3c6ef4712774b"
    author                               = "Tenable"

  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_segments > 0 and elf.number_of_sections > 0 and not (for any i in (0..elf.number_of_segments): ((elf.segments[i].offset <= elf.entry_point) and ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and for any j in (0..elf.number_of_sections): (elf.sections[j].offset <= elf.entry_point and ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) == (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset)))))
}

rule fake_dynamic_symbols: critical {
  meta:
    description = "binary with fake dynamic symbol table"
    family      = "Obfuscation"
    filetype    = "ELF"
    author      = "Tenable"

  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_sections > 0 and elf.dynamic_section_entries > 0 and for any i in (0..elf.dynamic_section_entries): (elf.dynamic[i].type == elf.DT_SYMTAB and not (for any j in (0..elf.number_of_sections): (elf.sections[j].type == elf.SHT_DYNSYM and for any k in (0..elf.number_of_segments): ((elf.segments[k].virtual_address <= elf.dynamic[i].val) and ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset))))
}
