
rule iptables : medium {
  meta:
    description = "interacts with the iptables firewall"
    ref = "https://www.netfilter.org/projects/iptables/"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_8907 = "89073097e72070cc7cc73c178447b70e07b603ccecfe406fe92fe9eafaae830f"
  strings:
    $ref = "iptables" fullword
  condition:
    any of them
}


rule nftables : medium {
  meta:
    description = "interacts with the nftables firewall"
    ref = "https://www.netfilter.org/projects/iptables/"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_8907 = "89073097e72070cc7cc73c178447b70e07b603ccecfe406fe92fe9eafaae830f"
  strings:
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
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
  strings:
    $systemctl = /systemctl[\w\- ]{0,16} (stop|disable) iptables/
    $service = /service[\w\- ]{0,16} iptables (stop|disable)/
  condition:
    any of them
}

rule iptables_flush : medium {
  meta:
    description = "flushes firewall rules"
    ref = "https://www.netfilter.org/projects/iptables/"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2023_Linux_Malware_Samples_1f94 = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
  strings:
    $ref = /iptables -F[\w]{0,16}/
  condition:
    any of them
}

rule iptables_delete : medium {
  meta:
    description = "deletes firewall rules"
    ref = "https://www.netfilter.org/projects/iptables/"
  strings:
    $ref = /iptables -X[\w]{0,16}/
  condition:
    any of them
}
