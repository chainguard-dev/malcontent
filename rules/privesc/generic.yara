rule runWithPrivileges: high {
  meta:
    description = "runs with privileges"

  strings:
    $ref = "runWithPrivileges"

  condition:
    any of them
}
