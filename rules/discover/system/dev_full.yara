rule dev_full: low linux {
  meta:
    description = "tests full disk behavior"

  strings:
    $val = "/dev/full" fullword

  condition:
    $val
}
