rule zsh_history: high {
  meta:
    description = "accesses zsh shell history"

  strings:
    $ref = ".zsh_history" fullword

  condition:
    all of them
}

