rule geoip_crypto_exec : notable {
  meta:
	description = "crypto, geolocation, and program execution"
    hash_hash_2015_trojan_Eleanor_conn = "5c16f53276cc4ef281e82febeda254d5a80cd2a0d5d2cd400a3e9f4fc06e28ad"
  strings:
    $geoip = "geoip"
    $crypto = "crypto"

    $exec = "execve"
	$execvp = "execvp"
	$exec_go = "os/exec"

    $not_unsupported = "not supported in this build"
	$not_http_server = "http/server"
	$not_geojson = "geojson"
  condition:
    $geoip and $crypto and any of ($exec*) and none of ($not*)
}
