rule hardcoded_onion: high {
  meta:
    description = "Contains hardcoded TOR onion address"

  strings:
    $ref        = /[a-z0-9]{56}\.onion/
    $not_listen = "listen.onion"

  condition:
    $ref and none of ($not*)
}
