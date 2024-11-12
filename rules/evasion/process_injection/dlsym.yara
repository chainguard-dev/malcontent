rule locate_dlsym: high link {
  meta:
    description = "searches for dynamic library symbols"

  strings:
    $locate_dlsym = "locate_dlsym"
    $libpam_sym   = /\w{0,8}libpam_sym\w{0,8}/
    $libdl_sym    = /\w{0,8}libdl_sym\w{0,8}/

  condition:
    filesize < 1MB and any of them
}
