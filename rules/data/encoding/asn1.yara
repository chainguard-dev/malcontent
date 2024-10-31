rule go_asn1: harmless {
  strings:
    $gocsv     = "encoding/asn1"
    $unmarshal = "asn1.parse"

  condition:
    any of them
}
