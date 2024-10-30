rule ipp_request {
  meta:
    pledge      = "inet"
    description = "Makes IPP (Internet Printing Protocol) requests"

  strings:
    $ref  = "ippPort"
    $ref2 = "ipp://"

  condition:
    any of them
}
