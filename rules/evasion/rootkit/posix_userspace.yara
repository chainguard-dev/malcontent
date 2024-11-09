rule readdir_intercept_source: high {
  meta:
    description = "userland rootkit source designed to hide files (DECLARE_READDIR)"
    filetypes   = "so,c"

  strings:
    $declare = "DECLARE_READDIR"
    $hide    = "hide"

  condition:
    filesize < 200KB and all of them
}
