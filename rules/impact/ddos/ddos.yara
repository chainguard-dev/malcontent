rule tsource_engine_query: critical {
  meta:
    description                       = "Performs DDoS (distributed denial of service) attacks"
    hash_2023_Unix_Malware_Agent_6fbb = "6fbbbd21cd5895553e7caf2d8d77e96e5dfe88095f970a8704ce472eb1eb219b"
    hash_2023_Unix_Trojan_Gafgyt_28e1 = "28e1a958b781f23cdea4e7ec1a1a7458c75004daaf2847362335f9d07358cf4f"
    hash_2023_Unix_Trojan_Gafgyt_5636 = "5636cddb43765a7e9228c88bd9f5c4cef443da2add0f7b7a9b77cead9387f5db"

  strings:
    $tsource = "TSource Engine Query"

  condition:
    $tsource
}

rule tcp_flood_refs: high {
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

rule flooder: high {
  meta:
    description                          = "References an IP flooder"
    hash_2023_Downloads_21ca             = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2024_Downloads_a031             = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"

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
    description              = "References DDoS"
    hash_2023_Downloads_039e = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
    hash_2023_UPX_11e5       = "11e557e139b44494dd243510b398bb2ac1037055c565d25ef86f04773f9b0389"
    hash_2023_UPX_11e557e139 = "4bcb87c9cd36f49d91a795b510ac1d38ea78b538b59f88cc161cdb54390d2bce"

  strings:
    $ref  = "DDoS" fullword
    $ref2 = "DD0S" fullword

  condition:
    any of them
}
