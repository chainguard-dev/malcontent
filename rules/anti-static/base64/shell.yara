rule base64_shell: high {
  meta:
    description = "Contains base64 shell script"
    filetypes   = "bash,sh,zsh"

  strings:
    $if     = "aWYgW1sg"
    $then   = "XV07IHR"
    $ostype = "JE9TVFl"

  condition:
    any of them
}

rule base64_shell_base64: critical {
  meta:
    description = "Contains base64 encoded base64 command"
    filetypes   = "bash,sh,zsh"

  strings:
    $base64 = "YmFzZTY0IC"

  condition:
    any of them
}
