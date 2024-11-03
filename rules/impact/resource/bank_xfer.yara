rule bank_xfer: medium {
  meta:
    description = "references 'bank transfer'"

  strings:
    $bank_transfer = "bank transfer"

  condition:
    any of them
}
