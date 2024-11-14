rule executable_calls_zip: medium {
  meta:
    description = "command shells out to zip"

    hash_2021_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"

  strings:
    $a_zip_x    = "zip -X"
    $a_zip_r    = "zip -r"
    $hash_bang  = "#!"
    $not_applet = "zip -r ../applet.zip"

  condition:
    any of ($a*) and not $hash_bang in (0..2) and none of ($not*)
}
