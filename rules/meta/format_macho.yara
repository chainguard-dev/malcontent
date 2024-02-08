rule macho {
  strings:
    $not_jar = "META-INF/"
    $not_dwarf = "_DWARF"
    $not_kext = "_.SYMDEF SORTED"
  condition:
    (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and none of ($not*)
}