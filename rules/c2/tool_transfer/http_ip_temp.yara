rule http_hardcoded_ip_dev_shm: critical exfil {
  meta:
    description = "hardcoded IP address + persistent temp dir"

  strings:
    // each octet is 10-255: single-digit octets were never matched, and an
    // octet above 255 (e.g. the "https://12.34.567.89" doc example) cannot be an address
    $ipv4 = /https*:\/\/((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])[:\/\w\-\?\.]{0,32}/

    // every exclusion spells out the octets $ipv4 needs, so each one cancels
    // exactly one $ipv4 match: link-local cloud metadata (169.254.169.254 for
    // AWS/GCP/Azure, 169.254.42.42 for Scaleway), Alibaba's 100.100.100.200,
    // the 11.11.11.x placeholder, and the RFC 1918 private ranges
    $not_link_local = /https*:\/\/169\.254\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])/
    $not_100        = /https*:\/\/100\.100\.100\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])/
    $not_11         = /https*:\/\/11\.11\.11\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])/
    $not_10         = /https*:\/\/10\.((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])\.){2}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])/
    $not_172        = /https*:\/\/172\.(1[6-9]|2[0-9]|3[01])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])/
    $not_192        = /https*:\/\/192\.168\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9])/

    $tmp_dev_shm    = "/dev/shm"
    $tmp_dev_mqueue = "/dev/mqueue"
    $tmp_var_tmp    = "/var/tmp"

  condition:
    // the known-good addresses are themselves $ipv4 matches, so subtract their
    // counts instead of switching the rule off: a cloud metadata or private-range
    // URL no longer excuses a second hardcoded address in the same file
    $ipv4 and any of ($tmp*) and #ipv4 > #not_link_local + #not_100 + #not_11 + #not_10 + #not_172 + #not_192
}
