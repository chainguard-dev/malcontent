rule geoip_crypto_exec: medium {
  meta:
    description = "crypto, geolocation, and program execution"

  strings:
    $geoip           = "geoip"
    $crypto          = "crypto"
    $exec            = "execve"
    $execvp          = "execvp"
    $exec_go         = "os/exec"
    $not_unsupported = "not supported in this build"
    $not_http_server = "http/server"
    $not_geojson     = "geojson"

  condition:
    $geoip and $crypto and any of ($exec*) and none of ($not*)
}
