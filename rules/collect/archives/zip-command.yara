rule executable_calls_zip: medium {
  meta:
    description = "command shells out to zip"

  strings:
    $a_zip_x    = "zip -X"
    $a_zip_r    = "zip -r"
    $hash_bang  = "#!"
    $not_applet = "zip -r ../applet.zip"

  condition:
    // "zip -r ../applet.zip" holds exactly one $a_zip_r match and no $a_zip_x, so
    // subtracting its count keeps the applet packaging line excused while any
    // additional zip invocation in the same file still fires
    #a_zip_x + #a_zip_r > #not_applet and not $hash_bang in (0..2)
}
