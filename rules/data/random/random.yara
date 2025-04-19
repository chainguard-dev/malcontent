rule random : low {
  meta:
    description = "uses a random number generator"

  strings:
    $ref = /\w{0,16}random\w{0,16}/ fullword
    $ref2 = /\w{0,16}Random\w{0,16}/ fullword

  condition:
    any of them
}
