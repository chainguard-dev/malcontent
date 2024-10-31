rule content_type {
  meta:
    pledge      = "inet"
    description = "set HTTP response encoding format (example: gzip)"
    ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding"

  strings:
    $ref = "Accept-Encoding"

  condition:
    any of them
}
