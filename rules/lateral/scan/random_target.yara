rule random_target: medium {
  meta:
    description                = "References a random target"
    hash_2024_Downloads_384e   = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
    hash_2023_pan_chan_b9e6    = "b9e643a8e78d2ce745fbe73eb505c8a0cc49842803077809b2267817979d10b0"
    hash_2024_enumeration_nmap = "353fd20c9efcd0328cea494f32d3650b9346fcdb45bfe20d8dbee2dd7b62ca62"

  strings:
    $ref  = "random target"
    $ref2 = "RandomTarget"
    $ref3 = "randomIP"
    $ref4 = "getrandip" fullword

  condition:
    any of them
}
