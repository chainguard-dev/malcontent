rule tiny_copy_run_delete: critical {
  meta:
    description = "copy executable, run, and delete"

  strings:
    $cp            = "cp -f"
    $rm            = /rm [\-\w ]{0,4}f[ \$\w\/\.]{0,32}/
    $null          = "/dev/null"
    $path_tmp      = "/tmp"
    $path_bin      = "/bin"
    $path_var      = "/var/"
    $path_dev_shm  = "/dev/shm"
    $run_quoted    = /\"\$[\w\-\/\$]{1,12}\"/ fullword
    $run_dot_slash = /\.\/[\-\w\$]{1,12}/ fullword
    $run_absolute  = /&& \/[\w\/\.]{0,32}/ fullword

  condition:
    filesize < 512 and $cp and $rm and $null and any of ($path*) and any of ($run*)
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

private rule run_delete_py_fetcher: medium {
  meta:
    description = "fetches content"
    filetypes   = "py"

  strings:
    $http_requests      = "requests.get" fullword
    $http_requests_post = "requests.post" fullword
    $http_urllib        = "urllib.request" fullword
    $http_urlopen       = "urlopen" fullword
    $git_git            = /git.Git\(.{0,64}/
    $http_curl          = "curl" fullword
    $http_wget          = "wget" fullword

  condition:
    any of them
}

rule python_setsid_remove: high {
  meta:
    description = "fetch, run in background, delete"
    filetypes   = "py"

  strings:
    $subprocess = /subprocess.\w{1,32}\([\"\'\/\w\ \-\)]{0,64}/
    $setsid     = "os.setsid"
    $remove     = "os.remove("

  condition:
    filesize < 1MB and all of them and run_delete_py_fetcher and @remove > @subprocess and @remove - @subprocess < 256
}

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
