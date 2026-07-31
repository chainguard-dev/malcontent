rule dev_mem: medium linux {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access raw system memory"

  strings:
    $val        = "/dev/mem"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword
    // fullword dropped so this count tracks $val exactly: in a binary with packed
    // string data the error text can be followed by a word character, which would
    // hide the $not while $val still matched
    $not_no     = "no /dev/mem"

  condition:
    // "/dev/mem" is a substring of the "no /dev/mem" error string, so count that
    // accepted spelling out instead of letting it disarm the rule; the two <paths.h>
    // macros only identify a paths.h consumer when both are present
    filesize < 10MB and uint32(0) == 1179403647 and #val > #not_no and not all of ($not_cshell, $not_rwho)
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
