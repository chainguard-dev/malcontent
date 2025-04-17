rule obfuscated_caller_base64_str_replace: critical {
  meta:
    description = "creatively hidden forms of the term 'base64'"

  strings:
    $a = /\wba\ws\we64/
    $b = /\wb\wa\wse\w6\w4/
    $c = /\wba\ws\we\w6\w4/
    $d = /\wb\was\we\w6\w4/
    $e = /\wb\wa\ws\we6\w4/
    $f = /\wb\wa\ws\we\w64/
    $g = "'bas'.'e'.'6'.'4"
    $h = "'ba'.'se'.'6'.'4"
    $i = "'b'.'ase'.'6'.'4"
    $j = "'bas'.'e'.'6'.'4"

    $not_unrelated1 = "_bias_eb604"

  condition:
    any of them and none of ($not*)
}
