rule decrypt: low {
  meta:
    description = "decrypts data"

  strings:
    $encrypt = /[\w ]{0,16}Decrypt[\w ]{0,16}/

  condition:
    any of them
}
