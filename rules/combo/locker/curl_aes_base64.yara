
rule curl_base64_aes {
  strings:
    $curl_easy = "curl_easy_"
    $aes_key = "aes_key"
    $base64 = "base64"
  condition:
    all of them
}
