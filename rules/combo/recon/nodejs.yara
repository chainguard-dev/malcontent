
rule npm_sysinfoexfil : high {
  meta:
    description = "may gather and exfiltrate system information"
    hash_2023_botbait = "1b92cb3d4b562d0eb05c3b2f998e334273ce9b491bc534d73bcd0b4952ce58d2"
  strings:
    $proc1 = "process.platform"
    $proc2 = "process.arch"
    $proc3 = "process.versions"
    $h = "http.request"
    $post = "POST"
  condition:
    filesize < 33554432 and $h and $post and any of ($proc*)
}
