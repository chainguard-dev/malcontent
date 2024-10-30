rule brute_force {
  meta:
    description = "May use bruteforce to function"

  strings:
    $ref  = "brute force" fullword
    $ref1 = "bruteforce" fullword
    $ref2 = "brute-force" fullword

  condition:
    any of them
}
