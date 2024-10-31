rule curses: harmless {
  meta:
    description = "uses the curses terminal database"

  strings:
    $ref  = "setupterm" fullword
    $ref2 = "set_curterm" fullword
    $ref3 = "vidputs" fullword

  condition:
    any of them
}
