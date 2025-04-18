rule zsh_history: high {
  meta:
    description = "accesses zsh shell history"

  strings:
    $ref              = ".zsh_history" fullword
    $not_appsec_rules = "\"id\": \"crs-930-120\""

  condition:
    $ref and none of ($not*)
}

rule zsh_history_editor: override {
  meta:
    description = "editor"
    zsh_history = "medium"

  strings:
    $ref = ".zsh_history" fullword

    $not_VIMRUNTIME = "VIMRUNTIME"

  condition:
    $ref and any of ($not*)
}
