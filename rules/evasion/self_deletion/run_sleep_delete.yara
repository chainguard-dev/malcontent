rule run_sleep_delete: critical {
  meta:
    description = "run executable, sleep, and delete"

  strings:
    $chmod     = /chmod [\-\+\w \$\@\{\w\/\.]{0,64}/
    $dot_slash = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
    $sleep     = /sleep \d{1,2}/ fullword
    $rm        = /rm \.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword

  condition:
    filesize < 64KB and all of them
}

rule fetch_run_sleep_delete: critical {
  meta:
    description = "fetch, run executable, sleep, and delete"

  strings:
    $url           = /https*:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $sleep         = /sleep \d{1,2}/ fullword
    $rm            = /rm [\-\w ]{0,4}f[ \$\w\/\.]{0,32}/
    $path_tmp      = "/tmp"
    $path_var      = "/var/"
    $path_dev_shm  = "/dev/shm"
    $run_quoted    = /\"\$[\-\w\/\$]{1,12}\"/ fullword
    $run_dot_slash = /\.\/[\-\w\$]{1,12}/ fullword

  condition:
    filesize < 1KB and $url and $sleep and $rm and any of ($path*) and any of ($run*)
}
