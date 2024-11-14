rule xor_mozilla: critical {
  meta:
    description = "XOR'ed user agent, often found in backdoors"
    author      = "Florian Roth"

  strings:
    $Mozilla_5_0 = "Mozilla/5.0" ascii wide xor(1-255)

  condition:
    any of them
}
