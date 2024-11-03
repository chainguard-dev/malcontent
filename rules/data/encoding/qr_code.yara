rule qr_code: low {
  meta:
    description = "works with QR Codes"

  strings:
    $ref = "QR Code"

  condition:
    any of them
}
