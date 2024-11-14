rule dev_full: harmless linux {
  meta:
    description = "tests full disk behavior"

  strings:
    $val = "/dev/full" fullword

  condition:
    $val
}
