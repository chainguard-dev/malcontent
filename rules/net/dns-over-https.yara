rule doh_refs: medium {
  meta:
    description                          = "Supports DNS (Domain Name Service) over HTTPS"
    hash_2023_Downloads_21ca             = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2023_Linux_Malware_Samples_1020 = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2023_Linux_Malware_Samples_24f3 = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"

  strings:
    $doh_Provider = "doh.Provider"
    $DnsOverHttps = "DnsOverHttps"
    $contentType  = "application/dns-message"
    $dnspod       = "dnspod"
    $doh_url      = "doh-url" fullword

  condition:
    any of them
}
