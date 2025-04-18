rule bash_history: medium {
  meta:
    description = "accesses bash shell history"

  strings:
    $ref = ".bash_history"

  condition:
    all of them
}

rule bash_history_high: high {
  meta:
    description = "accesses bash shell history"

  strings:
    $ref           = ".bash_history"
    $not_posix     = "POSIXLY_CORRECT"
    $not_source    = "BASH_SOURCE"
    $not_cshrc     = ".cshrc"
    $not_sonarqube = "Statically serving hidden files is security-sensitive"

  condition:
    $ref and none of ($not*)
}
