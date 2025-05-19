rule javascript_dropper: critical {
  meta:
    description = "Javascript dropper"
    filetypes   = "js,ts"

  strings:
    $lh                = /require\(['"]https{0,1}['"]\)/
    $lh_axios          = /require\(['"]axios{0,1}['"]\)/
    $lib_fs            = /require\(['"]fs['"]\)/
    $lib_child_process = /require\(['"]child_process['"]\)/
    $http              = "http://"
    $https             = "https://"
    $dir_temp          = "TEMP"
    $dir_home          = "os.homedir"
    $other_unlink      = ".unlink"
    $other_create      = ".createWriteStream"
    $other_http        = "http.get"
    $other_method      = "method: 'GET'"

  condition:
    filesize < 3KB and all of ($lib*) and any of ($lh*) and any of ($dir*) and any of ($http*) and 2 of ($other*)
}
