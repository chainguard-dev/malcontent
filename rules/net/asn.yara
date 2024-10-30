rule asn {
  meta:
    description = "Uses ASN (Autonomous System Numbers)"

  strings:
    $dnsmessage = "asn number"

  condition:
    any of them
}
