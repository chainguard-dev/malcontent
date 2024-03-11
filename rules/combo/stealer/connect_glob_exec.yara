rule http_digest_auth_exec_connector : suspicious {
  meta:
    hash_DoubleFantasy_mdworker = "502a80f81cf39f6c559ab138a39dd4ad5fca697dbca4a62b36527be9e55400f5"
	description = "Uses HTTP Digest auth, runs programs, uses glob"
  strings:
    $d_connect = "CONNECT"
    $d_digest = "Digest"
    $d_https = "https"
    $d_rspauth = "rspauth"
    $d_exec = "_exec"
    $d_connect_f = "_connect"
    $d_glob = "_glob"
  condition:
    all of ($d_*)
}

rule connect_glob_exec_https : notable {
  meta:
	description = "makes HTTPS connections, runs programs, finds files"
  strings:
    $d_https = "https"
    $d_exec = "_exec"
    $d_connect_f = "_connect"
    $d_glob = "_glob"
  condition:
    all of ($d_*)
}
