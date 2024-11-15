rule firefox_master_password: high {
  meta:
    description = "Decrypts Firefox master password"

  strings:
    $firefox    = "Firefox"
    $nssPrivate = "nssPrivate"

  condition:
    all of them
}
