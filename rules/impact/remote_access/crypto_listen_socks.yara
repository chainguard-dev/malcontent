rule socks_crypto_listener: medium {
  meta:
    description = "listens, uses SOCKS5, and cryptography"

  strings:
    $s_socks     = "SOCKS" fullword
    $s_SOCKS5    = "SOCKS5" fullword
    $s_socks5    = "socks5" fullword
    $f_listen    = "listen" fullword
    $f_crypto    = "crypto"
    $not_ssh     = "SSH_AUTH_SOCK"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_nc      = "usage: nc"
    $not_kitty   = "KITTY_KITTEN_RUN_MODULE"
    $not_js      = "function("

    // these three co-occur in the Kolide launcher; on its own "LAUNCHER_DEBUG"
    // is an ordinary env-var name and "log.(*Logger)" is in every Go binary
    // that uses the standard log package, so the set is required as a whole
    $notgrp_kolide_option = "KOLIDE_LAUNCHER_OPTION"
    $notgrp_kolide_debug  = "LAUNCHER_DEBUG"
    $notgrp_kolide_logger = "log.(*Logger)"

  condition:
    filesize < 26214400 and any of ($s*) and all of ($f*) and none of ($not_*) and not all of ($notgrp_kolide*)
}
