rule link {
  meta:
    syscall     = "link"
    pledge      = "cpath"
    description = "May create hard file links"

  strings:
    $ref = "_link" fullword

  condition:
    any of them
}

rule linkat {
  meta:
    syscall     = "linkat"
    description = "May create hard file links"
    pledge      = "cpath"

  strings:
    $rename = "linkat" fullword

  condition:
    any of them
}
