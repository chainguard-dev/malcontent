rule pivot_root: medium {
  meta:
    capability  = "CAP_SYS_SYSADMIN"
    description = "change the root mount location"
    syscall     = "pivot_root"

  strings:
    $ref       = "pivot_root" fullword
    $not_pivot = "no_pivot_root"

  condition:
    // fullword treats _ as a delimiter, so $ref also matches inside the accepted
    // "no_pivot_root" spelling. Counting instead requires a pivot_root occurrence
    // that "no_pivot_root" does not account for: each accepted spelling cancels
    // exactly the one $ref match it contains.
    #ref > #not_pivot
}
