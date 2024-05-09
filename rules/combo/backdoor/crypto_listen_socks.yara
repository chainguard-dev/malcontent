
rule socks_crypto_listener : medium {
  meta:
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_04b5 = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
  strings:
    $s_socks = "SOCKS" fullword
    $s_SOCKS5 = "SOCKS5" fullword
    $s_socks5 = "socks5" fullword
    $f_listen = "listen" fullword
    $f_crypto = "crypto"
    $not_ssh = "SSH_AUTH_SOCK"
    $not_kolide = "KOLIDE_LAUNCHER_OPTION"
    $not_launcher = "LAUNCHER_DEBUG"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_nc = "usage: nc"
    $not_kitty = "KITTY_KITTEN_RUN_MODULE"
    $not_logger = "log.(*Logger)"
    $not_js = "function("
  condition:
    filesize < 26214400 and any of ($s*) and all of ($f*) and none of ($not*)
}
