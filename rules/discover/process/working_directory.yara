rule getcwd: harmless {
  meta:
    pledge      = "rpath"
    syscall     = "getcwd"
    description = "gets current working directory"

  strings:
    $getcwd = "getcwd" fullword

  condition:
    any of them
}

rule getwd: harmless {
  meta:
    pledge      = "rpath"
    syscall     = "getwd"
    description = "gets current working directory"

  strings:
    $getwd    = "getwd" fullword
    $go_Getwd = "Getwd" fullword

  condition:
    any of them
}

rule pwd: low {
  meta:
    description = "gets current working directory"

  strings:
    $pwd = /["']pwd['"]/ fullword

  condition:
    any of them
}
