
rule iptables : notable {
  meta:
    description = "interacts with the iptables/nftables firewall"
    ref = "https://www.netfilter.org/projects/iptables/"
  strings:
    $ref = "iptables" fullword
    $ref2 = "nftables" fullword
  condition:
    any of them
}

rule iptables_disable : critical {
  meta:
    description = "stops or disables the iptables firewall"
    ref = "https://www.netfilter.org/projects/iptables/"
    hash_2023_Unix_Malware_Agent_b79a = "b79af4e394cbc8c19fc9b5410fa69b10325fd23f58bec330954caae135239a1f"
    hash_2023_Unix_Trojan_IptabLex_b574 = "b5745c865ab5348425e79ce91d79442982c20f3f89e1ffcdd2816895a25d2a1c"
  strings:
    $systemctl = /systemctl[\w\- ]{0,16} (stop|disable) iptables/
    $service = /service[\w\- ]{0,16} iptables (stop|disable)/
  condition:
    any of them
}

rule iptables_flush : notable {
  meta:
    description = "flushes firewall rules"
    ref = "https://www.netfilter.org/projects/iptables/"
  strings:
    $ref = /iptables -F[\w]{0,16}/
  condition:
    any of them
}

rule iptables_delete : notable {
  meta:
    description = "deletes firewall rules"
    ref = "https://www.netfilter.org/projects/iptables/"
    hash_2023_BPFDoor_8b84 = "8b84336e73c6a6d154e685d3729dfa4e08e4a3f136f0b2e7c6e5970df9145e95"
    hash_2023_BPFDoor_8b9d = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"
  strings:
    $ref = /iptables -X[\w]{0,16}/
  condition:
    any of them
}
