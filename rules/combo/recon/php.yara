
rule python_sysinfo_http : suspicious {
  meta:
    description = "exfiltrate system information"
    hash_2023_libcurl_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2024_aaa_bbb_ccc_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2023_setuptool_setuptool_setup = "50c9a683bc0aa2fbda3981bfdf0bbd4632094c801b224af60166376e479460ec"
  strings:
    $r_user = "getpass.getuser"
    $r_hostname = "socket.gethostname"
    $r_platform = "platform.platform"
    $u = /[\w\.]{0,16}urlopen/
  condition:
    filesize < 4096 and any of ($r*) and any of ($u*)
}
