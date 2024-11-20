rule bash_history: high {
  meta:
    description = "accesses bash shell history"


  strings:
    $ref = ".bash_history" fullword

  condition:
    all of them
}

rule bash: override {
  meta:
    description  = "bash"
    bash_history = "medium"

  strings:
    $posix  = "POSIXLY_CORRECT"
    $source = "BASH_SOURCE"

  condition:
    filesize > 100KB and filesize < 2MB and all of them
}
