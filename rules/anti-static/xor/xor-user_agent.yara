rule xor_mozilla: critical {
  meta:
    description                   = "XOR'ed user agent, often found in backdoors"
    author                        = "Florian Roth"
    hash_2023_Tiganie_S3npai_29ae = "29ae9389dcb1f5b0bc3a52543b3ddfc933a65c4943709907fd136decf717255c"

  strings:
    $Mozilla_5_0 = "Mozilla/5.0" ascii wide xor(1-255)

  condition:
    any of them
}
