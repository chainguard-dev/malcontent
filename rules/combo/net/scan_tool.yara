
rule generic_scan_tool : medium {
  meta:
    description = "may scan networks"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
  strings:
    $f_gethostbyname = "gethostbyname"
    $f_socket = "socket"
    $f_connect = "connect"
    $o_banner = "banner"
    $o_Probe = "Probe"
    $o_probe = "probe"
    $o_scan = "scan"
    $o_port = "port"
    $o_target = "target"
    $not_nss = "NSS_USE_SHEXP_IN_CERT_NAME"
    $not_microsoft = "Microsoft Corporation"
    $not_php_reference = "ftp_nb_put"
  condition:
    all of ($f*) and 2 of ($o*) and none of ($not*)
}
