
rule go_scan_tool_val : medium {
  meta:
    description = "Uses struct with JSON representations for host:port"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2024_Downloads_7c63 = "7c636f1c9e4d9032d66a58f263b3006788047488e00fc26997b915e9d1f174bf"
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"
  strings:
    $j_port = "json:\"port\""
    $j_hostname = "json:\"hostname\""
    $j_host = "json:\"host\""
    $j_hip = "json:\"ip\""
  condition:
    $j_port and any of ($j_h*)
}
