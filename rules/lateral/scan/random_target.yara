rule random_target: medium {
  meta:
    description              = "References a random target"

    hash_2023_pan_chan_b9e6  = "b9e643a8e78d2ce745fbe73eb505c8a0cc49842803077809b2267817979d10b0"

  strings:
    $ref  = "random target"
    $ref2 = "RandomTarget"
    $ref3 = "randomIP"
    $ref4 = "getrandip" fullword

  condition:
    any of them
}
