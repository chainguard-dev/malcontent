
rule base64_gz : medium {
  meta:
    description = "Contains base64 gzip content"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2024_Deobfuscated_LocusShell_4fe93cfac7416fee810b7333ea4a6a513339429c = "8ffe7774d9bbd92c0e3674d52c8b8f37745cad8278c68be8685bcae76365e8e5"
  strings:
    $header = "H4sIA"
  condition:
    $header
}


rule base64_gz_small : high {
  meta:
    description = "Contains base64 gzip content"
  strings:
    $header = "H4sIA"
  condition:
    filesize < 32KB and $header
}
