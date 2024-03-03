rule selinux_firewall : suspicious{
  meta:
    hash_2023_installer_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
  strings:
    $selinux = /SELINUX[=\w]{0,32}/ fullword
    $f_iptables = /iptables[ -\w]{0,32}/
    $f_firewalld = /[\w ]{0,32}firewalld/

	$not_ip6tables = "NFTNL_RULE_TABLE"
	$not_iptables = "iptables-restore"
	$not_iptables_nft = "iptables-nft"
  condition:
	$selinux and any of ($f*) and none of ($not*)
}
