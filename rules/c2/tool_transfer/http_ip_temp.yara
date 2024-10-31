rule http_hardcoded_ip_dev_shm: critical exfil {
  meta:
    description = "hardcoded IP address + persistent temp dir"

  strings:
    $ipv4         = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}[:\/\w\-\?\.]{0,32}/
    $not_metadata = "http://169.254.169.254"
    $not_100      = "http://100.100.100"
    $not_11       = "http://11.11.11"
    $not_192      = "http://192.168"

    $tmp_dev_shm    = "/dev/shm"
    $tmp_dev_mqueue = "/dev/mqueue"
    $tmp_var_tmp    = "/var/tmp"

  condition:
    $ipv4 and any of ($tmp*) and none of ($not*)
}
