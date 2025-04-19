rule sketchy_parseint_math: medium {
  meta:
    description = "complex math and string to integer conversion"

  strings:
    $m1 = /\d{2,16}[\-\+\*\^]\w{1,8}/
    $m2 = /\w{1,8}[\-\+\*\^]\d{2,16}/
    $f_parseInt = "parseInt"
  condition:
    filesize < 1MB and any of ($f*) and ((#m1 > 5) or (#m2 > 5))
}
