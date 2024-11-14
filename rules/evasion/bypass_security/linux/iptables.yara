rule iptables: medium {
  meta:
    description = "interacts with the iptables firewall"
    ref         = "https://www.netfilter.org/projects/iptables/"

  strings:
    $ref = "iptables" fullword

  condition:
    any of them
}

rule nftables: medium {
  meta:
    description = "interacts with the nftables firewall"
    ref         = "https://www.netfilter.org/projects/iptables/"

  strings:
    $ref2 = "nftables" fullword

  condition:
    any of them
}

rule iptables_disable: critical {
  meta:
    description                       = "stops or disables the iptables firewall"
    ref                               = "https://www.netfilter.org/projects/iptables/"
    hash_2023_Unix_Malware_Agent_b79a = "b79af4e394cbc8c19fc9b5410fa69b10325fd23f58bec330954caae135239a1f"

  strings:
    $systemctl = /systemctl[\w\- ]{0,16} (stop|disable) iptables/
    $service   = /service[\w\- ]{0,16} iptables (stop|disable)/

  condition:
    any of them
}

rule iptables_flush: medium {
  meta:
    description = "flushes firewall rules"
    ref         = "https://www.netfilter.org/projects/iptables/"

  strings:
    $ref = /iptables -F[\w]{0,16}/

  condition:
    any of them
}

rule iptables_delete: medium {
  meta:
    description = "deletes firewall rules"
    ref         = "https://www.netfilter.org/projects/iptables/"

  strings:
    $ref = /iptables -X[\w]{0,16}/

  condition:
    any of them
}
