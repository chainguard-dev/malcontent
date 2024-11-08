rule worm: medium {
  meta:
    description = "References 'Worm'"

  strings:
    $ref3 = "Worm" fullword
    $ref2 = /w{0,8}worm/ fullword

  condition:
    any of them
}
