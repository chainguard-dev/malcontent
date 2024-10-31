rule rename_system_binary: high {
  meta:
    description                          = "Renames system binary"
    hash_2023_OrBit_f161                 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"

  strings:
    $ref = /(mv|cp|ln) \/(bin|usr\/bin)\/[ \.\w\/]{0,64}/

  condition:
    $ref
}
