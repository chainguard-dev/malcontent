rule hacktool_chisel: critical {
  meta:
    description = "fast TCP/UDP tunnel tool, commonly used in attacks"

  strings:
    $chisel = "jpillora/chisel"
    $f1     = "tlsLetsEncrypt"
    $f2     = "authUser"
    $f3     = "StartContext"
    $f4     = "handleWebsocket"
    $f5     = "tlsKeyCert"
    $f7     = "tunnel_out_ssh"

  condition:
    $chisel or 4 of ($f*)
}
