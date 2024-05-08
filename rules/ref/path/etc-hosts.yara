
rule etc_hosts : notable {
  meta:
    description = "references /etc/hosts"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
  strings:
    $ref = "/etc/hosts"
  condition:
    any of them
}
