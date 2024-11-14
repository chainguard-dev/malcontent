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
    description              = "References an IP flooder"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"

  strings:
    $ = "flooder" fullword
    $ = "FLOODER" fullword
    $ = "Flood operation"
    $ = "Starting Flood"
    $ = "stresser" fullword
    $ = "dosia" fullword
    $ = "ICMPFLOOD" fullword
    $ = "BLACKNURSE" fullword
    $ = "HYDRASYN" fullword
    $ = "KAFFER-SLAP" fullword

  condition:
    any of them
}

rule ddos: medium {
  meta:
    description = "References DDoS"

    hash_2023_UPX_11e5 = "11e557e139b44494dd243510b398bb2ac1037055c565d25ef86f04773f9b0389"

  strings:
    $ref  = "DDoS" fullword
    $ref2 = "DD0S" fullword

  condition:
    any of them
}
