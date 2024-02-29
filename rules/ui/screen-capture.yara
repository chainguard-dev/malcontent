rule macos_screencapture_caller : suspicious {
  meta:
    hash_2019_Macma_AgentB = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
    hash_2021_Macma_CDDS_UserAgent = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
    hash_2017_Perl_FruitFly_A = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_2017_Perl_FruitFly_quimitchin = "ce07d208a2d89b4e0134f5282d9df580960d5c81412965a6d1a0786b27e7f044"
    hash_2017_Perl_FruitFly_spaud = "befa9bfe488244c64db096522b4fad73fc01ea8c4cd0323f1cbdee81ba008271"
    hash_2021_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
    hash_2021_MacMa_qmfus = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
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
  meta:
    hash_2021_CDDS_arch = "a63466d09c3a6a2596a98de36083b6d268f393a27f7b781e52eeb98ae055af97"
    hash_2021_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
    hash_2021_MacMa_qmfus = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
  strings:
    $capture_screen = "captureScreen"
    $cg_window = "CGWindowListCreateImageFromArray"
    $not_private = "/System/Library/PrivateFrameworks"
    $not_nuclei = "projectdiscovery"
	$not_microsoft = "Microsoft Corporation"
  condition:
    1 of ($c*) and none of ($not*)
}
