rule url_encode: medium {
  meta:
    description = "encodes URL, likely to pass GET variables"

  strings:
    $ref = "urlencode"

  condition:
    any of them
}
