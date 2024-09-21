
rule base64_str_replace : medium {
  meta:
    description = "creatively hidden forms of the term 'base64'"
    hash_2024_2024_Inull_Studio_err = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"
    hash_2024_2024_Inull_Studio_err = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"
    hash_2024_2024_Inull_Studio_godzilla_xor_base64 = "699c7bbf08d2ee86594242f487860221def3f898d893071426eb05bec430968e"
  strings:
    $a = /ba.s.e64/
    $b = /b.a.s.6.4/
    $c = /b.a.se.6.4/
  condition:
    any of them
}


rule gzinflate_str_replace : critical {
  meta:
    description = "creatively hidden forms of the term 'gzinflate'"
  strings:
    $a = /g.z.inf.l.a/
    $b = /g.z.i.n.f.l/
    $c = /g.z.in.f.l/
  condition:
    any of them
}