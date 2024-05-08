
rule generic_scan_tool : notable {
  meta:
    description = "may scan networks"
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
