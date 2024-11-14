rule rename_system_binary: high {
  meta:
    description          = "Renames system binary"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"

  strings:
    $ref = /(mv|cp|ln) \/(bin|usr\/bin)\/[ \.\w\/]{0,64}/

  condition:
    $ref
}
