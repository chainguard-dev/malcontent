rule putty_ssh_sessions_reference {
  strings:
    $putty = "Software\\SimonTatham\\PuTTY\\Sessions"

  condition:
    any of them
}
