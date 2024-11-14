rule executable_calls_zip: medium {
  meta:
    description = "command shells out to zip"

  strings:
    $a_zip_x    = "zip -X"
    $a_zip_r    = "zip -r"
    $hash_bang  = "#!"
    $not_applet = "zip -r ../applet.zip"

  condition:
    any of ($a*) and not $hash_bang in (0..2) and none of ($not*)
}
