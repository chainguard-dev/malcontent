rule go_scan_tool_val: medium {
  meta:
    description              = "Uses struct with JSON representations for host:port"



  strings:
    $j_port     = "json:\"port\""
    $j_hostname = "json:\"hostname\""
    $j_host     = "json:\"host\""
    $j_hip      = "json:\"ip\""

  condition:
    $j_port and any of ($j_h*)
}
