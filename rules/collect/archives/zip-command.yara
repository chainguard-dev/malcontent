rule executable_calls_zip: medium {
  meta:
    description                    = "command shells out to zip"
    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
    hash_2021_CDDS_UserAgent_v2021 = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
    hash_2021_CDDS_client          = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"

  strings:
    $a_zip_x    = "zip -X"
    $a_zip_r    = "zip -r"
    $hash_bang  = "#!"
    $not_applet = "zip -r ../applet.zip"

  condition:
    any of ($a*) and not $hash_bang in (0..2) and none of ($not*)
}
