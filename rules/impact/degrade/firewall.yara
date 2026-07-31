import "math"

rule selinux_firewall: high linux {
  meta:
    filetypes   = "elf,so"
    description = "references both SELinux and iptables/firewalld"

  strings:
    $selinux          = /SELINUX[=\w]{0,32}/ fullword
    $f_iptables       = /iptables[ -\\w]{0,32}/
    $f_firewalld      = /[\w ]{0,32}firewalld/
    $not_ip6tables    = "NFTNL_RULE_TABLE"
    $not_iptables     = "iptables-restore"
    $not_iptables_nft = "iptables-nft"
    $not_selinux_init = "SELINUX_INIT" fullword
    $not_define       = "#define" fullword
    $not_netlink      = "NETLINK" fullword
    $not_containerd   = "containerd" fullword

  condition:
    // $selinux matches SELINUX_INIT and $f_iptables matches the iptables-restore
    // and iptables-nft tool names, so those are compared by count rather than
    // membership; $not_selinux_init carries $selinux's fullword modifier so the
    // two cannot drift. The remaining four are independent netfilter/container
    // runtime fingerprints and stay membership tests.
    filesize < 1MB and $selinux and #selinux > #not_selinux_init and
    (#f_iptables > #not_iptables + #not_iptables_nft or $f_firewalld) and
    none of ($not_ip6tables, $not_define, $not_netlink, $not_containerd)
}

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

rule firewall_iptables_disable: high {
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
