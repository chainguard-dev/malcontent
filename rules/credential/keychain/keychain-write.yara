rule keychain_write {
  meta:
    description = "Writes contents to the Keychain"

  strings:
    $ref = "WriteDataToKeychain"

  condition:
    any of them
}
