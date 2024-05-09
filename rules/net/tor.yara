
rule tor_user : high {
  meta:
    ref_eleanor = "https://www.malwarebytes.com/blog/news/2016/07/new-mac-backdoor-malware-eleanor"
    description = "Makes use of the TOR/.onion protocol"
    hash_2023_Conti_bb64 = "bb64b27bff106d30a7b74b3589cc081c345a2b485a831d7e8c8837af3f238e1e"
    hash_2023_Multios_Ransomware_DarkSide_da3b = "da3bb9669fb983ad8d2ffc01aab9d56198bd9cedf2cc4387f19f4604a070a9b5"
    hash_2023_Downloads_039e = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
  strings:
    $t_tor_addr = "_tor_addr"
    $t_tor = "TOR Browser" nocase
    $t_hidden_service_port = "HiddenServicePort" nocase
    $t_go = "go-libtor"
    $t_rust = "libtor" fullword
    $not_drop = "[.onion] drop policy"
    $not_bug = "Tor Browser bug"
  condition:
    filesize < 20971520 and any of ($t*) and none of ($not*)
}
