
rule socks_directory_scanner : notable {
  meta:
    hash_2023_cobaltstrike_beacon = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"
    hash_2023_ciscotools_4247 = "42473f2ab26a5a118bd99885b5de331a60a14297219bf1dc1408d1ede7d9a7a6"
  strings:
    $s_socks = "SOCKS" fullword
    $s_socks5 = "socks5" fullword
    $s_SOCKS5 = "SOCKS5"
    $d_readdir = "readdir" fullword
    $not_ssh = "SSH_AUTH_SOCK"
    $not_kolide = "KOLIDE_LAUNCHER_OPTION"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_launcher = "LAUNCHER_DEBUG"
    $not_kitten = "KITTY_KITTEN_RUN_MODULE"
	$not_js = "function("
  condition:
    filesize < 26214400 and any of ($s*) and any of ($d*) and none of ($not*)
}