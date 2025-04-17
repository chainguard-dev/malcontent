rule dev_mem: medium linux {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access raw system memory"

  strings:
    $val        = "/dev/mem"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword
    $not_no     = "no /dev/mem" fullword

  condition:
    filesize < 10MB and uint32(0) == 1179403647 and $val and none of ($not*)
}

rule comsvcs_minidump: high windows {
  meta:
    description = "dump process memory using comsvcs.ddl"
    author      = "Florian Roth"

  strings:
    $ref = /comsvcs(\.dll)?[, ]{1,2}(MiniDump|#24)/

  condition:
    any of them
}

rule memdump: medium {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "dumps system memory"

  strings:
    $ = "memdump" fullword
    $ = "dumpmem" fullword

  condition:
    filesize < 10MB and any of them
}
