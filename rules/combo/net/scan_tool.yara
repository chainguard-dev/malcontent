rule generic_scan_tool : notable {
  meta:
	description = "May perform network scanning"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2022_trojan_Winnti = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2023_Downloads_b56a = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2021_miner_malxmr = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2021_CoinMiner_TB_Camelot = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
  strings:
    $f_gethostbyname = "gethostbyname"
    $f_socket = "socket"
    $f_connect = "connect"

    $o_banner = "banner"
    $o_Probe = "Probe"
    $o_probe = "probe"
    $o_scan = "scan"
    $o_port = "port"

	$not_nss = "NSS_USE_SHEXP_IN_CERT_NAME"
	$not_microsoft = "Microsoft Corporation"
	$not_php_reference = "ftp_nb_put"
  condition:
    all of ($f*) and any of ($o*) and none of ($not*)
}
