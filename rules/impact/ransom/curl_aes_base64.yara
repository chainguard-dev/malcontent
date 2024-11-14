rule curl_base64_aes: medium {
  meta:
    hash_2019_C_unioncryptoupdater = "631ac269925bb72b5ad8f469062309541e1edfec5610a21eecded75a35e65680"

  strings:
    $curl_easy = "curl_easy_"
    $aes_key   = "aes_key"
    $base64    = "base64"
    $unlink    = "unlink" fullword

  condition:
    filesize < 100KB and all of them
}
