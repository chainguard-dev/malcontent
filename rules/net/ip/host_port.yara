rule go_scan_tool_val: medium {
  meta:
    description = "Uses struct with JSON representations for host:port"

  strings:
    $j_port     = "json:\"port\""
    $j_hostname = "json:\"hostname\""
    $j_host     = "json:\"host\""
    $j_hip      = "json:\"ip\""

  condition:
    $j_port and any of ($j_h*)
}

rule host_port: medium {
  meta:
    description = "connects to an arbitrary host:port"

  strings:
    $host_port = /host.{0,12}port/

  condition:
    any of them
}

rule hostname_port: medium {
  meta:
    description = "connects to an arbitrary hostname:port"

  strings:
    $hostname = "hostname" fullword
    $port     = "port" fullword

  condition:
    all of them
}

rule port_number: medium {
  meta:
    description = "references a 'port number'"

  strings:
    $port_sp_number = "port number" fullword
    $port_number    = "port_number" fullword

  condition:
    any of them
}
