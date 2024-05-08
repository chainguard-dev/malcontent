
rule macos_screencapture_caller : suspicious {
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
