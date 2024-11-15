rule socks_crypto_listener: medium {
  meta:
    description = "listens, uses SOCKS5, and cryptography"

  strings:
    $s_socks      = "SOCKS" fullword
    $s_SOCKS5     = "SOCKS5" fullword
    $s_socks5     = "socks5" fullword
    $f_listen     = "listen" fullword
    $f_crypto     = "crypto"
    $not_ssh      = "SSH_AUTH_SOCK"
    $not_kolide   = "KOLIDE_LAUNCHER_OPTION"
    $not_launcher = "LAUNCHER_DEBUG"
    $not_private  = "/System/Library/PrivateFrameworks/"
    $not_nc       = "usage: nc"
    $not_kitty    = "KITTY_KITTEN_RUN_MODULE"
    $not_logger   = "log.(*Logger)"
    $not_js       = "function("

  condition:
    filesize < 26214400 and any of ($s*) and all of ($f*) and none of ($not*)
}
