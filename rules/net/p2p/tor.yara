rule tor_user: high {
  meta:
    ref_eleanor = "https://www.malwarebytes.com/blog/news/2016/07/new-mac-backdoor-malware-eleanor"
    description = "Makes use of the TOR/.onion protocol"

  strings:
    $t_tor_addr            = "_tor_addr"
    $t_tor                 = "TOR Browser" nocase
    $t_hidden_service_port = "HiddenServicePort" nocase
    $t_go                  = "go-libtor"
    $t_rust                = "libtor" fullword
    $t_relay               = "relay.tor2socks."
    $t_tor2web             = ".tor2web"
    $not_drop              = "[.onion] drop policy"
    $not_bug               = "Tor Browser bug"

  condition:
    filesize < 20971520 and any of ($t*) and none of ($not*)
}
