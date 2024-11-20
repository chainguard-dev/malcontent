rule zsh_history: medium {
  meta:
    description = "access .zsh file"

  strings:
    $ref = ".zsh_history" fullword

  condition:
    all of them
}
