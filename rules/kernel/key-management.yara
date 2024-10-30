rule syscall_keyctl {
  meta:
    syscall     = "keyctl"
    description = "kernel key management facility"

  strings:
    $ref = "keyctl"

  condition:
    any of them
}

