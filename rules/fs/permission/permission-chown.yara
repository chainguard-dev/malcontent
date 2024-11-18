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
    description = "Changes file ownership"
    pledge      = "wpath"
    syscall     = "fchown"
    capability  = "CAP_CHOWN"

  strings:
    $chown = "Chown" fullword

  condition:
    any of them
}

rule takeown: medium windows {
  meta:
    description = "takes ownership of files"

  strings:
    $takeown = /(takeown|TAKEOWN)/

  condition:
    any of them
}

rule takeown_force: high windows {
  meta:
    description = "forcibly takes ownership of files recursively"

  strings:
    $takeown_fr = /(takeown|TAKEOWN).{1,8}\/[fF].{1,8}\/[rR] .{0,32}[yY]/
    $takeown_rf = /(takeown|TAKEOWN).{1,8}\/[rR].{1,8}\/[fF] .{0,32}[yY]/

  condition:
    any of them
}
