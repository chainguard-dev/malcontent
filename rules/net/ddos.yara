rule ddos_refs : critical {
  meta:
    description = "Performs DDoS (distributed denial of service) attacks"
    hash_2023_Unix_Malware_Agent_6fbb = "6fbbbd21cd5895553e7caf2d8d77e96e5dfe88095f970a8704ce472eb1eb219b"
    hash_2023_Unix_Trojan_Gafgyt_28e1 = "28e1a958b781f23cdea4e7ec1a1a7458c75004daaf2847362335f9d07358cf4f"
    hash_2023_Unix_Trojan_Gafgyt_5636 = "5636cddb43765a7e9228c88bd9f5c4cef443da2add0f7b7a9b77cead9387f5db"
  strings:
    $ref = "TSource Engine Query"
    $ref2 = "ackflood" fullword
    $ref3 = "synflood" fullword
    // datadog-agent tracer-fentry-debug.o
    $ignore_ref = /synflood\_\w+/
  condition:
    any of ($ref*) and not $ignore_ref
}
