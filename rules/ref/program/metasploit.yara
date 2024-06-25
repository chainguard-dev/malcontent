
rule metasploit : high {
  meta:
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2013_GetShell = "4863d9a15f3a1ed5dd1f84cf9883eafb6bf2b483c2c6032cfbf0d3caf3cf6dd8"
    hash_2024_Deobfuscated_1n73ctionShell_abc00305dcfabe889507832e7385af937b94350d = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
  strings:
    $ref = "metasploit"
  condition:
    $ref
}
