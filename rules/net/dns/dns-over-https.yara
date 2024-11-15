rule doh_refs: medium {
  meta:
    description = "Supports DNS (Domain Name Service) over HTTPS"

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
