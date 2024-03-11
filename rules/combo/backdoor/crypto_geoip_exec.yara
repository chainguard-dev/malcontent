
rule geoip_crypto_shell : suspicious {
  meta:
    hash_hash_2015_trojan_Eleanor_conn = "5c16f53276cc4ef281e82febeda254d5a80cd2a0d5d2cd400a3e9f4fc06e28ad"
  strings:
    $s_geoip = "geoip"
    $s_crypto = "crypto"
    $s_exec = "exec"
    $not_unsupported = "not supported in this build"
  condition:
    all of ($s*) and none of ($not*)
}