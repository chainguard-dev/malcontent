
rule macos_screencapture_caller : high {
  meta:
    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
    hash_2021_CDDS_UserAgent_v2021 = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
    hash_2021_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
  strings:
    $screencap = "screencapture"
    $not_program = "@(#)PROGRAM:"
    $not_apple = "Copyright Apple Computer Inc"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_screencaptureui = "screencaptureui.app"
    $not_signal = "_availability_version_check"
  condition:
    $screencap and none of ($not_*)
}

rule macos_screen_capture {
  strings:
    $capture_screen = "captureScreen"
    $cg_window = "CGWindowListCreateImageFromArray"
    $not_private = "/System/Library/PrivateFrameworks"
    $not_nuclei = "projectdiscovery"
    $not_microsoft = "Microsoft Corporation"
  condition:
    1 of ($c*) and none of ($not*)
}
