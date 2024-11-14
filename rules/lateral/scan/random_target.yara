rule random_target: medium {
  meta:
    description = "References a random target"

  strings:
    $ref  = "random target"
    $ref2 = "RandomTarget"
    $ref3 = "randomIP"
    $ref4 = "getrandip" fullword

  condition:
    any of them
}
