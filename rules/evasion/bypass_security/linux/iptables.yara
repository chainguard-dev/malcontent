rule iptables: medium {
  meta:
    description = "interacts with the iptables firewall"
    ref         = "https://www.netfilter.org/projects/iptables/"

    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_8907 = "89073097e72070cc7cc73c178447b70e07b603ccecfe406fe92fe9eafaae830f"

  strings:
    $ref = "iptables" fullword

  condition:
    any of them
}

rule nftables: medium {
  meta:
    description = "interacts with the nftables firewall"
    ref         = "https://www.netfilter.org/projects/iptables/"

    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_8907 = "89073097e72070cc7cc73c178447b70e07b603ccecfe406fe92fe9eafaae830f"

  strings:
    $ref2 = "nftables" fullword

  condition:
    any of them
}

rule iptables_disable: critical {
  meta:
    description                         = "stops or disables the iptables firewall"
    ref                                 = "https://www.netfilter.org/projects/iptables/"
    hash_2023_Unix_Malware_Agent_b79a   = "b79af4e394cbc8c19fc9b5410fa69b10325fd23f58bec330954caae135239a1f"
    hash_2023_Unix_Trojan_IptabLex_b574 = "b5745c865ab5348425e79ce91d79442982c20f3f89e1ffcdd2816895a25d2a1c"

  strings:
    $systemctl = /systemctl[\w\- ]{0,16} (stop|disable) iptables/
    $service   = /service[\w\- ]{0,16} iptables (stop|disable)/

  condition:
    any of them
}

rule iptables_flush: medium {
  meta:
    description              = "flushes firewall rules"
    ref                      = "https://www.netfilter.org/projects/iptables/"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

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
