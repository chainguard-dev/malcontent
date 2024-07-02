rule tsource_engine_query : critical {
  meta:
    description = "Performs DDoS (distributed denial of service) attacks"
    hash_2023_Unix_Malware_Agent_6fbb = "6fbbbd21cd5895553e7caf2d8d77e96e5dfe88095f970a8704ce472eb1eb219b"
	hash_2023_Unix_Trojan_Gafgyt_28e1 = "28e1a958b781f23cdea4e7ec1a1a7458c75004daaf2847362335f9d07358cf4f"
    hash_2023_Unix_Trojan_Gafgyt_5636 = "5636cddb43765a7e9228c88bd9f5c4cef443da2add0f7b7a9b77cead9387f5db"
  strings:
    $tsource = "TSource Engine Query"
  condition:
    $tsource
}

rule tcp_flood_refs : high {
  meta:
    description = "May performs DDoS (distributed denial of service) attacks"
  strings:
    $ack2 = "ack flood" fullword
    $ack3 = "ACK flood" fullword
    $ack = "ackflood" fullword

    $syn2 = "syn flood" fullword
    $syn3 = "SYN flood" fullword
    $syn = "synflood" fullword
  condition:
    (any of ($ack*) and any of ($syn*))
}
