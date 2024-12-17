rule xor_eval: medium {
  meta:
    description = "eval( xor'd"

  strings:
    $b_eval  = "eval(" xor(1-31)
    $b_eval2 = "eval(" xor(33-255)

  condition:
    any of ($b_*)
}
