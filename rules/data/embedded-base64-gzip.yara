
rule base64_gz : notable {
  meta:
    description = "Contains base64 gzip content"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $header = "H4sIA"
  condition:
    $header
}
