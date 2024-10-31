rule unsetenv: harmless {
  strings:
    $ref = "unsetenv" fullword

  condition:
    any of them
}
