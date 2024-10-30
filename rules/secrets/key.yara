rule from_secret_key: high {
  meta:
    description = "extracts data from a secret key"

  strings:
    $key = "fromSecretKey"

  condition:
    $key
}
