rule infected: medium {
  meta:
    description = "References being 'infected'"

  strings:
    $ref  = "infected"
    $ref2 = "INFECTED"

  condition:
    filesize < 5MB and any of them
}

rule infection: medium {
  meta:
    description = "References 'infection'"

  strings:
    $ref3 = "infection"

  condition:
    filesize < 5MB and any of them
}

rule infected_with: high {
  meta:
    description = "References 'infected with'"

  strings:
    $ref = /.{3,16} infected with .{3,16}/

  condition:
    filesize < 5MB and $ref
}
