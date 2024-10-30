rule chown: harmless {
  meta:
    description = "May change file ownership"
    pledge      = "wpath"
    syscall     = "chown"
    capability  = "CAP_CHOWN"

  strings:
    $chown = "chown" fullword

  condition:
    any of them
}

rule fchown {
  meta:
    description = "May change file ownership"
    pledge      = "wpath"
    syscall     = "fchown"
    capability  = "CAP_CHOWN"

  strings:
    $chown = "fchown" fullword

  condition:
    any of them
}

rule fchownat {
  meta:
    description = "May change file ownership"
    pledge      = "wpath"
    syscall     = "fchown"
    capability  = "CAP_CHOWN"

  strings:
    $chown = "fchownat" fullword

  condition:
    any of them
}

rule Chown: medium {
  meta:
    description              = "Changes file ownership"
    pledge                   = "wpath"
    syscall                  = "fchown"
    capability               = "CAP_CHOWN"
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"

  strings:
    $chown = "Chown" fullword

  condition:
    any of them
}
