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
    $not_bug               = "Tor Browser bug" nocase

  // $t_tor matches inside $not_bug, so a single bug reference used to exempt the
  // other six markers as well. Only $t_tor is discounted, and by occurrence count
  // rather than presence, so a file that both cites a bug and uses TOR still
  // fires. $not_bug carries nocase to match $t_tor, keeping the counts paired.

  condition:
    filesize < 20971520 and (any of ($t_tor_addr, $t_hidden_service_port, $t_go, $t_rust, $t_relay, $t_tor2web) or #t_tor > #not_bug) and not $not_drop
}
