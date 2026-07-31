rule http_hardcoded_ip_dev_shm: critical exfil {
  meta:
    description = "hardcoded IP address + persistent temp dir"

  strings:
    $ipv4         = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}[:\/\w\-\?\.]{0,32}/
    $not_metadata = "http://169.254.169.254"

    // $ipv4 requires four 2-3 digit octets, so the bare "http://100.100.100",
    // "http://11.11.11" and "http://192.168" prefixes also covered addresses $ipv4
    // can never match, such as http://192.168.1.1; spelling out the octets the
    // regex needs makes each of these cancel exactly one $ipv4 match
    $not_100 = /https*:\/\/100\.100\.100\.[1-9][0-9]{1,2}/
    $not_11  = /https*:\/\/11\.11\.11\.[1-9][0-9]{1,2}/
    $not_192 = /https*:\/\/192\.168\.[1-9][0-9]{1,2}\.[1-9][0-9]{1,2}/

    $tmp_dev_shm    = "/dev/shm"
    $tmp_dev_mqueue = "/dev/mqueue"
    $tmp_var_tmp    = "/var/tmp"

  condition:
    // the known-good addresses are themselves $ipv4 matches, so subtract their
    // counts instead of switching the rule off: a cloud metadata or private-range
    // URL no longer excuses a second hardcoded address in the same file
    $ipv4 and any of ($tmp*) and #ipv4 > #not_metadata + #not_100 + #not_11 + #not_192
}
