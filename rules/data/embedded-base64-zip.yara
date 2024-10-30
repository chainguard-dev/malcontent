rule base64_zip: high {
  meta:
    description = "Contains base64 zip file content"

  strings:
    $header = "UEsDBB"

  condition:
    $header
}
