rule bin_su {
  meta:
    description = "Calls /bin/su"

  strings:
    $ref = "/bin/su"

  condition:
    any of them
}
