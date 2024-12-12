rule osqueryd: override {
  meta:
    description  = "osqueryd"
    bash_history = "medium"
    zsh_history  = "medium"

  strings:
    $ref = "OSQUERY_WORKER" fullword

  condition:
    filesize < 100MB and any of them
}

