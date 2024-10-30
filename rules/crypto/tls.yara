rule tls {
  strings:
    $go         = "crypto/tls"
    $tlsversion = "TLSVersion"
    $TLS123     = "TLS13"
    $tls123     = "tls123"

  condition:
    any of them
}
