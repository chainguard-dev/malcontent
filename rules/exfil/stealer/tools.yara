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

  condition:
    any of ($a*) and none of ($not*)
}
