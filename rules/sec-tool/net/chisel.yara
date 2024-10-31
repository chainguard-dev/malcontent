rule hacktool_chisel: critical {
  meta:
    description                   = "fast TCP/UDP tunnel tool, commonly used in attacks"
    hash_2024_pivoting_chisel_x32 = "76bd8bd2cf2e28f8b17adb2c077bc55309aae08f507af77ee15c0a9455cb889c"
    hash_2024_pivoting_chisel_x64 = "c237f1a3f75b2759f66ec741448bb352e95e186a9a689f87c8641b44a13d878b"

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
