rule previewers_alike: high {
  meta:
    description               = "uploads, accesses a keychain, uses ZIP files"
    hash_2024_2024_Previewers = "20b986b24d86d9a06746bdb0c25e21a24cb477acb36e7427a8c465c08d51c1e4"

  strings:
    $upload   = "upload"
    $zip      = "zip"
    $keychain = "keychain_item"

  condition:
    all of them
}
