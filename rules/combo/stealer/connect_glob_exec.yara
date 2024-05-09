
rule http_digest_auth_exec_connector : high {
  meta:
    description = "Uses HTTP Digest auth, runs programs, uses glob"
  strings:
    $d_connect = "CONNECT"
    $d_digest = "Digest"
    $d_https = "https"
    $d_rspauth = "rspauth"
    $d_exec = "_exec" fullword
    $d_connect_f = "_connect" fullword
    $d_glob = "_glob" fullword
  condition:
    all of ($d_*)
}

rule connect_glob_exec_https : medium {
  meta:
    description = "makes HTTPS connections, runs programs, finds files"
    hash_2020_BirdMiner_arachnoidal = "904ad9bc506a09be0bb83079c07e9a93c99ba5d42ac89d444374d80efd7d8c11"
  strings:
    $d_https = "https"
    $d_exec = "_exec" fullword
    $d_connect_f = "_connect" fullword
    $d_glob = "_glob" fullword
  condition:
    all of ($d_*)
}
