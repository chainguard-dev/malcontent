import "math"

rule selinux_firewall: high linux {
  meta:
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
    filetypes                            = "elf,so"
    description                          = "references both SELinux and iptables/firewalld"

  strings:
    $selinux          = /SELINUX[=\w]{0,32}/ fullword
    $f_iptables       = /iptables[ -\w]{0,32}/
    $f_firewalld      = /[\w ]{0,32}firewalld/
    $not_ip6tables    = "NFTNL_RULE_TABLE"
    $not_iptables     = "iptables-restore"
    $not_iptables_nft = "iptables-nft"
    $not_selinux_init = "SELINUX_INIT"
    $not_define       = "#define" fullword
    $not_netlink      = "NETLINK" fullword
    $not_containerd   = "containerd" fullword

  condition:
    filesize < 1MB and $selinux and any of ($f*) and none of ($not*)
}

import "math"

private rule ufw_tool {
  strings:
    $not_route         = "route-insert"
    $not_statusverbose = "statusverbose"
    $not_enables_the   = "enables the"
    $not_enable_the    = "enable the"
    $not_enable        = "ufw enable"

  condition:
    filesize < 256KB and any of them
}

rule ufw_disable_word: high {
  meta:
    description = "disables ufw firewall"

  strings:
    $ref = /ufw['", ]{1,4}disable/ fullword

  condition:
    filesize < 256KB and $ref and not ufw_tool
}

rule iptables_disable: high {
  meta:
    description = "disables iptables firewall"

  strings:
    $input   = "iptables -P INPUT ACCEPT"
    $output  = "iptables -P OUTPUT ACCEPT"
    $forward = "iptables -P FORWARD ACCEPT"
    $flush   = "iptables -F"

  condition:
    filesize < 1MB and 3 of them
}

rule netsh_firewall: high windows {
  meta:
    description = "adds exception to Windows netsh firewall"

  strings:
    $netsh          = "netsh"
    $firewall       = "firewall"
    $firewall2      = "advfirewall"
    $allowedprogram = /allowedprogram.{0,64}ENABLE/

  condition:
    $netsh and any of ($firewall*) and $allowedprogram
}

rule netsh_firewall_split: high windows {
  meta:
    description = "adds exception to Windows netsh firewall"

  strings:
    $netsh          = "netsh"
    $firewall       = "firewall"
    $firewall2      = "advfirewall"
    $allowedprogram = "allowedprogram"
    $ENABLE         = "ENABLE"

  condition:
    filesize < 5MB and $netsh and any of ($firewall*) and $allowedprogram and $ENABLE
}
