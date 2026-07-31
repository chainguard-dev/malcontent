rule kmem: high bsd {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access raw kernel memory"

  strings:
    $val = "/dev/kmem"

    // entries from include/paths.h
    $notpaths_cshell = "_PATH_CSHELL" fullword
    $notpaths_rwho   = "_PATH_RWHODIR" fullword

    $not_lsof = "lsof" fullword

  condition:
    // the two _PATH_ macros only identify a copy of include/paths.h when they
    // appear together, so require the whole pair; "lsof" is conclusive alone.
    $val and not $not_lsof and not all of ($notpaths*)
}
