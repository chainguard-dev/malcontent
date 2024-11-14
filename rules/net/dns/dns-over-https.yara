rule doh_refs: medium {
  meta:
    description              = "Supports DNS (Domain Name Service) over HTTPS"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"

  strings:
    $doh_Provider = "doh.Provider"
    $DnsOverHttps = "DnsOverHttps"
    $contentType  = "application/dns-message"
    $dnspod       = "dnspod"
    $doh_url      = "doh-url" fullword
    $cloudflare   = "https://9.9.9.9/dns-query"

  condition:
    any of them
}
