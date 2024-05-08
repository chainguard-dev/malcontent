
rule curl_base64_aes : medium {
  meta:
    hash_2023_Linux_Malware_Samples_df3b = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2019_C_unioncryptoupdater = "631ac269925bb72b5ad8f469062309541e1edfec5610a21eecded75a35e65680"
  strings:
    $curl_easy = "curl_easy_"
    $aes_key = "aes_key"
    $base64 = "base64"
  condition:
    filesize < 52428800 and all of them
}
