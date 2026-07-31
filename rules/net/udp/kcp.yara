rule kcp_go: medium {
  meta:
    description = "uses kcp-go, a reliable UDP library for Go"
    filetypes   = "elf,go,macho"

  strings:
    $k_waitsnd       = "ikcp_waitsnd"
    $k_cmd_wins      = "IKCP_CMD_WINS"
    $u_ssdp_discover = "ssdp:discover"
    $u_addr          = "239.255.255.250"
    $not_igd         = "UPnP/IGD"
    $not_c1          = "CaptureOne"

  // The $not_* strings are exclusions, so they must not be selectable as
  // evidence: quantify over the reference strings only.

  condition:
    any of ($k*, $u_*) and none of ($not*)
}
