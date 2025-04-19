rule decode_uri_component: medium {
  meta:
    description = "decodes URL components"

  strings:
    $ref = "decodeURIComponent"

  condition:
    filesize < 1MB and $ref
}
