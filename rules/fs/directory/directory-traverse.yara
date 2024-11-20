rule fts {
  meta:
    description = "traverse filesystem hierarchy"
    syscall     = "openat,getdents"
    pledge      = "rpath"

  strings:
    $fts_open     = "_fts_open" fullword
    $fts_read     = "_fts_read" fullword
    $fts_children = "_fts_children" fullword
    $fts_set      = "_fts_set" fullword
    $fts_close    = "_fts_close" fullword

  condition:
    2 of them
}

rule py_walk: medium {
  meta:
    description = "traverse filesystem hierarchy"

  strings:
    $walk = "os.walk"

  condition:
    any of them
}

rule find_term: medium {
  meta:
    description = "traverse filesystem hierarchy"

  strings:
    $find_files = "find_files"
    $ruby       = "next if entry == '.' || entry == '..'"
    $ruby2      = "next if file == __FILE__"

  condition:
    any of them
}
