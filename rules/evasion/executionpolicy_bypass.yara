rule ps_executionpolicy_bypass: high {
  meta:
    description = "bypasses PowerShell Execution Policy"

  strings:
    $ref = "-ExecutionPolicy Bypass"

  condition:
    filesize < 16KB and $ref
}

rule ps_executionpolicy_bypass_small_child: high {
  meta:
    description = "Calls powerscript and bypasses PowerShell Execution Policy"

  strings:
    $ref   = "-ExecutionPolicy Bypass"
    $child = /require\(['"]child_process['"]\);/

  condition:
    filesize < 16KB and all of them
}
