
rule dial_shared_screen_discovery : suspicious {
  meta:
    hash_2023_UPX_346d49f539e31f1caaa102385742761e4f8fbc8e7e0e9981a018d79cd908c6b2_elf_x86 = "9c33e6aad8862369c6d1e8bc87daa568dc5ff44bc49a109d8bcafdbce626556c"
    hash_2023_UPX_5e0df7eb8b71c031a40c7c6998df3e1916411aea9a3c17f37247723caacd488c_elf_x86 = "36b793d08cb5716e5351a29b4c84ff96ceeb92b458a5283f06cec7a4e56545db"
  strings:
    $urn_multiscreen = "urn:dial-multiscreen-org:service:dial:1"
    $not_chromium = "RasterCHROMIUM"
  condition:
    $urn_multiscreen and none of ($not*)
}
