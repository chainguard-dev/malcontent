rule csv {
  meta:
    description = "Works with CSV (comma separated value) files"

  strings:
    $gocsv     = "gocsv."
    $unmarshal = "UnmarshalCSV"

  condition:
    any of them
}
