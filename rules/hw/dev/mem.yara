rule dev_mem: medium linux {
  meta:
    capability        = "CAP_SYS_RAWIO"
    description       = "access raw system memory"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"

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
