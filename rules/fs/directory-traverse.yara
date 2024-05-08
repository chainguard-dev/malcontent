
rule fts {
  meta:
    description = "traverse filesystem hierarchy"
    syscall = "openat,getdents"
    pledge = "rpath"
  strings:
    $fts_open = "_fts_open" fullword
    $fts_read = "_fts_read" fullword
    $fts_children = "_fts_children" fullword
    $fts_set = "_fts_set" fullword
    $fts_close = "_fts_close" fullword
  condition:
    2 of them
}

rule py_walk : notable {
  meta:
    description = "traverse filesystem hierarchy"
    hash_2024_scripts_sync_csv = "aa7a7ad320421cdbeb2f488318849c3494b8ecba4e0f9c3623c3c16287cdd55a"
    hash_2021_A_g = "ffb0a802fdf054d4988d68762d9922820bdc3728f0378fcd6c4ed28c06da5cf0"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
  strings:
    $walk = "os.walk"
  condition:
    any of them
}
