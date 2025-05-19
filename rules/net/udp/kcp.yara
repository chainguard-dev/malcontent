rule kcp_go: medium {
  meta:
    description = "uses kcp-go, a reliable UDP library for Go"
    filetypes   = "elf,go,macho"

  strings:
    $                = "ikcp_waitsnd"
    $                = "IKCP_CMD_WINS"
    $u_ssdp_discover = "ssdp:discover"
    $u_addr          = "239.255.255.250"
    $not_igd         = "UPnP/IGD"
    $not_c1          = "CaptureOne"

  condition:
    any of them
}
