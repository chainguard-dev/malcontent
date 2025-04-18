rule tsource_engine_query: critical {
  meta:
    description = "Performs DDoS (distributed denial of service) attacks"

  strings:
    $tsource = "TSource Engine Query"

  condition:
    $tsource
}

rule tcp_syn_ack_flood_refs: high {
  meta:
    description = "May perform DDoS (distributed denial of service) attacks"

  strings:
    $ack2 = "ack flood" fullword
    $ack3 = "ACK flood" fullword
    $ack  = "ackflood" fullword

    $syn2 = "syn flood" fullword
    $syn3 = "SYN flood" fullword
    $syn  = "synflood" fullword

  condition:
    any of ($ack*) and any of ($syn*)
}

rule ip_flood_refs: high {
  meta:
    description = "May perform DDoS (distributed denial of service) attacks"

  strings:
    $udp_flood    = "udp_flood"
    $tcp_flood    = "tcp_flood"
    $tcpraw_flood = "tcpraw_flood"

  condition:
    filesize < 1MB and any of them
}

rule flooder: high {
  meta:
    description = "References an IP flooder"

  strings:
    $               = "flooder" fullword
    $               = "FLOODER" fullword
    $               = "Flood operation"
    $               = "Starting Flood"
    $               = "stresser" fullword
    $               = "dosia" fullword
    $               = "ICMPFLOOD" fullword
    $               = "BLACKNURSE" fullword
    $               = "HYDRASYN" fullword
    $               = "KAFFER-SLAP" fullword
    $not_pypi_index = "testpack-id-lb001"

  condition:
    any of them and none of ($not*)
}

rule ddos: medium {
  meta:
    description = "References DDoS"

  strings:
    $ref  = "DDoS" fullword
    $ref2 = "DD0S" fullword

  condition:
    any of them
}
