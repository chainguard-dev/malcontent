
rule curl_base64_aes {
  meta:
    hash_2019_C_unioncryptoupdater = "631ac269925bb72b5ad8f469062309541e1edfec5610a21eecded75a35e65680"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
  strings:
    $curl_easy = "curl_easy_"
    $aes_key = "aes_key"
    $base64 = "base64"
  condition:
    all of them
}
