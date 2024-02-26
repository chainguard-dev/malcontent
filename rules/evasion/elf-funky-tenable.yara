import "elf"

rule single_load_rwe {
  meta:
    description = "Flags binaries with a single LOAD segment marked as RWE."
    family = "Stager"
    filetype = "ELF"
    hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"
    hash_2023_Linux_Malware_Samples_16e0 = "16e09592a9e85cd67530ec365ac2c50e48e873335c1ad0f984e3daaefc8a57b5"
    hash_2023_Linux_Malware_Samples_4c33 = "4c33e1ec01b8ad98f670ba6ec6792d23d1b5d3c399990f39ffd7299ac7c0646f"
    hash_2023_Linux_Malware_Samples_4ed5 = "4ed5c7939fdaa8ca9cfc6cd0dfe762bb68b58adb434f98c1a28aae53c3b96b00"
    hash_2023_Linux_Malware_Samples_5eb6 = "5eb69f3b46a0df45f5e4f2c0beede4a86f9aace3870dd8db28bc6521e69f363b"
    hash_2023_Linux_Malware_Samples_ae70 = "ae70ca051f29b058f18ed7aef33b750ddec69d05d08801cf3f99b121e41c0c4f"
    hash_2023_Linux_Malware_Samples_cb8d = "cb8d3fe305a2acaa34ebd37472fe4a966ed238e09d7f77164a1f53d850ea0294"
    hash_2023_Downloads_cd54 = "cd54a34dbd7d345a7fd7fd8744feb5c956825317e9225edb002c3258683947f1"
  condition:
    elf.number_of_segments == 1 and elf.segments[0].type == elf.PT_LOAD and elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address {
  meta:
    description = "A fake sections header has been added to the binary."
    family = "Obfuscation"
    filetype = "ELF"
    hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2023_Linux_Malware_Samples_19f7 = "19f76bf2be3ea11732f2c5c562afbd6f363b062c25fba3a143c3c6ef4712774b"
    hash_2023_Linux_Malware_Samples_1ce9 = "1ce94d788d01ae70782084d5dd48844ecf03629c3aaacff7f4bc35e59d4aaf55"
    hash_2023_Linux_Malware_Samples_1fce = "1fce1d5b977c38e491fe84e529a3eb5730d099a4966c753b551209f4a24524f3"
    hash_2023_Linux_Malware_Samples_25ba = "25ba8e1e4ae88297fa5715b9bdd68b059ccb128af1eb06d9ecce0181d48ae2c3"
    hash_2023_Linux_Malware_Samples_43fa = "43fab92516cdfaa88945996988b7cfe987f26050516503fb2be65592379d7d7f"
    hash_2023_Linux_Malware_Samples_4a77 = "4a77c23cb0f77b8b5f4c8bfc9ba786f9b08b910dc8b4d25f1eb6e07c29c600f1"
  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_segments > 0 and elf.number_of_sections > 0 and not (for any i in (0..elf.number_of_segments) : ((elf.segments[i].offset <= elf.entry_point) and ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and for any j in (0..elf.number_of_sections) : (elf.sections[j].offset <= elf.entry_point and ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) == (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset)))))
}

rule fake_dynamic_symbols {
  meta:
    description = "A fake dynamic symbol table has been added to the binary"
    family = "Obfuscation"
    filetype = "ELF"
    hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"
  condition:
    elf.type == elf.ET_EXEC and elf.entry_point < filesize and elf.number_of_sections > 0 and elf.dynamic_section_entries > 0 and for any i in (0..elf.dynamic_section_entries) : (elf.dynamic[i].type == elf.DT_SYMTAB and not (for any j in (0..elf.number_of_sections) : (elf.sections[j].type == elf.SHT_DYNSYM and for any k in (0..elf.number_of_segments) : ((elf.segments[k].virtual_address <= elf.dynamic[i].val) and ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset))))
}
