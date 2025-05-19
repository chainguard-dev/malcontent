rule virtualprotect: low windows {
  meta:
    description = "Changes the protection of virtual memory within the calling process"

  strings:
    $ref = "VirtualProtect" fullword

  condition:
    any of them
}

rule virtualprotect_py_crazy: high windows {
  meta:
    description = "Changes the protection of virtual memory within the calling process"
    filetypes   = "py"

  strings:
    $ref      = "ctypes.windll.kernel32.VirtualProtect" fullword
    $f_encode = "encode("
    $f_decode = "decode("
    $f_b64    = "b64decode("

  condition:
    filesize < 1MB and $ref and any of ($f*)
}

rule virtualprotect_ex: medium windows {
  meta:
    description = "Changes the protection of virtual memory within other processes"

  strings:
    $ref = "VirtualProtectEx" fullword

  condition:
    any of them
}
