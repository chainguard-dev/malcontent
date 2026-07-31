rule bash_dev_tcp: high exfil {
  meta:
    description = "uses /dev/tcp for network access (bash)"

  strings:
    $ref             = /\/dev\/tcp[\/\w\.]{8,16}\/\d{1,6}/
    $posixly_correct = "POSIXLY_CORRECT"

    $notgrp_gitlab_comment   = "# Check that both our processes are running on their tcp port"
    $notgrp_gitlab_get       = /GET \/ HTTP\/1\.1(\\n|\n){1,2}" >/
    $notgrp_gitlab_localhost = "/dev/tcp/127.0.0.1/8080"

    $not_lsof = "/proc/tcp" fullword

  condition:
    // The $notgrp_gitlab_* strings jointly identify the GitLab healthcheck script; on its
    // own the localhost:8080 endpoint is just another /dev/tcp use, which is what this
    // rule is looking for, so it must not suppress by itself.
    $ref and not $posixly_correct and not all of ($notgrp_gitlab*) and none of ($not_*)
}

rule bash_dev_tcp_hardcoded_ip: critical {
  meta:
    description = "hardcoded /dev/tcp host:port"

  strings:
    $dev_tcp            = /\/dev\/tcp\/[\w\.]{8,16}\/\d{1,6}/
    $not_comment        = "# Check that both our processes are running on their tcp port"
    $not_get            = /GET \/ HTTP\/1\.1(\\n|\n){1,2}" >/
    $not_localhost_8080 = "/dev/tcp/127.0.0.1/8080"

  condition:
    // The whole $not set is the GitLab healthcheck script; $not_localhost_8080 is itself a
    // $dev_tcp match, so require the full set rather than any single member.
    filesize < 1KB and $dev_tcp and not all of ($not*)
}
