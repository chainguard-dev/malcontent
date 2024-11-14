rule curl_base64_aes: medium {
  meta:

  strings:
    $curl_easy = "curl_easy_"
    $aes_key   = "aes_key"
    $base64    = "base64"
    $unlink    = "unlink" fullword

  condition:
    filesize < 100KB and all of them
}
