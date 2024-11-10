rule dev_full: medium linux {
  meta:
    description = "tests full disk behavior"

  strings:
    $val = "/dev/full" fullword

  condition:
    $val
}
