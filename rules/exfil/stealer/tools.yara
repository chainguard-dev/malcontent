rule stealer_executable_calls_archive_tool: medium {
  meta:
    description = "calls tool to create archive files"

  strings:
    $a_tar_c    = "tar -c"
    $a_tar_xf   = "tar xf"
    $a_tar_cf   = "tar cf"
    $a_tar_rX   = "tar -r -X"
    $a_tar_T    = "tar -T"
    $a_zip_x    = "zip -X"
    $a_zip_r    = "zip -r"
    $a_ditto    = /ditto -[\w\-\/ ]{0,32}/
    $not_applet = "zip -r ../applet.zip"
    $not_usage  = "Usage:"

  // "zip -r ../applet.zip" contains $a_zip_r verbatim, so an osacompile bundle
  // step used to suppress every archive-tool call in the file, including the
  // tar and ditto spellings it says nothing about. Only $a_zip_r is compared by
  // occurrence count against it; the other tool spellings are unaffected.

  condition:
    not $not_usage and (any of ($a_tar*) or $a_zip_x or $a_ditto or #a_zip_r > #not_applet)
}
