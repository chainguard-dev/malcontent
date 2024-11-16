rule tls {
  strings:
    $go         = "crypto/tls"
    $tlsversion = "TLSVersion"
    $TLS123     = "TLS13"
    $tls123     = "tls123"
    $require    = "require(\"tls\")"
    $require2   = "require('tls')"

  condition:
    any of them
}
