rule curl_base64_aes: medium {
  meta:
    description = "uses curl_easy, base64, and removes files"

  strings:
    $curl_easy = "curl_easy_"
    $aes_key   = "aes_key"
    $base64    = "base64"
    $unlink    = "unlink" fullword

  condition:
    filesize < 100KB and all of them
}
