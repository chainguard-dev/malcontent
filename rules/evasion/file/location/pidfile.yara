rule users_pid_file: high {
  meta:
    description = "unusual pid (process id) file location"

  strings:
    $p_users = /\/Users\/[%\w\.\-\/]{0,64}\.pid/

  condition:
    filesize < 100MB and any of ($p*)
}

rule hidden_pid_file: high {
  meta:
    description = "unusual pid (process id) file location"

  strings:
    $p_hidden = /[\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}\.pid/

  condition:
    filesize < 100MB and any of ($p*)
}

rule tmp_pid_file: high {
  meta:
    description = "unusual pid (process id) file location"

  strings:
    $p_tmp = /\/tmp\/[%\w\.\-\/]{0,64}\.pid/

  condition:
    filesize < 100MB and any of ($p*)
}

rule known_tmp_pid_file: override {
  meta:
    description  = "well-known pid file locations"
    tmp_pid_file = "medium"

  strings:
    $not_nginx       = "/tmp/nginx/nginx.pid"
    $not_intel_speed = "/tmp/hfi-events.pid"
    $not_podman      = "/tmp/pause.pid"

  condition:
    any of them
}
