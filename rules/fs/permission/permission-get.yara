rule getmode {
  meta:
    description = "looks up file permissions"
    pledge      = "rpath"

  strings:
    $_chmod = "_getmode"

  condition:
    any of them
}

rule icacls: windows {
  meta:
    description = "looks up file permissions via icacls"
    pledge      = "rpath"

  strings:
    $icacls = "icacls" fullword

  condition:
    any of them
}
