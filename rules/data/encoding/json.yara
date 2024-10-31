rule encoding_json {
  meta:
    description = "Supports JSON encoded objects"

  strings:
    $jsone = "encoding/json"

  condition:
    any of them
}
