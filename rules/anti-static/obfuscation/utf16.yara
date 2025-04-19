rule sketchy_fromCharCode_math: medium {
  meta:
    description = "complex math and utf16 code unit conversion"

  strings:
    $m1 = /\d{2,16}[\-\+\*\^]\w{1,8}/
    $m2 = /\w{1,8}[\-\+\*\^]\d{2,16}/
    $f_fromCharCode = "fromCharCode"
  condition:
    filesize < 1MB and any of ($f*) and ((#m1 > 5) or (#m2 > 5))
}

rule static_charcode_math : critical {
meta:
  description = "assembles strings from character codes and static integers"
strings:
  $ref = /fromCharCode\(\d{1,16}\s{0,2}[\-\+\*\^]{1,2}\d{1,16}/
condition:
  any of them
}
