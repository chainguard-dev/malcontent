rule bash_dev_tcp: high exfil {
  meta:
    description = "uses /dev/tcp for network access (bash)"

  strings:
    $ref                = /\/dev\/tcp[\/\w\.]{8,16}\/\d{1,6}/
    $posixly_correct    = "POSIXLY_CORRECT"
    $not_comment        = "# Check that both our processes are running on their tcp port"
    $not_get            = /GET \/ HTTP\/1.1\n{1,2} >/
    $not_localhost_8080 = "/dev/tcp/127.0.0.1/8080"
    $not_lsof           = "/proc/tcp" fullword

  condition:
    $ref and not $posixly_correct and none of ($not*)
}

rule bash_dev_tcp_hardcoded_ip: critical {
  meta:
    description = "hardcoded /dev/tcp host:port"

  strings:
    $dev_tcp            = /\/dev\/tcp\/[\w\.]{8,16}\/\d{1,6}/
    $not_comment        = "# Check that both our processes are running on their tcp port"
    $not_get            = /GET \/ HTTP\/1.1\n{1,2} >/
    $not_localhost_8080 = "/dev/tcp/127.0.0.1/8080"

  condition:
    filesize < 1KB and $dev_tcp and none of ($not*)
}
