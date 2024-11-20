rule zsh_history: high {
  meta:
    description = "accesses zsh shell history"

  strings:
    $ref = ".zsh_history" fullword

  condition:
    all of them
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
