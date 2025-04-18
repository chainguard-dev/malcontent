rule macos_screencapture_caller: high {
  meta:
    description = "captures screenshots via the 'screencapture' command"

  strings:
    $screencap           = "screencapture"
    $not_program         = "@(#)PROGRAM:"
    $not_apple           = "Copyright Apple Computer Inc"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_screencaptureui = "screencaptureui.app"
    $not_signal          = "_availability_version_check"
    $not_pypi_index      = "testpack-id-lb001"

  condition:
    $screencap and none of ($not_*)
}

rule py_screen_capture: high {
  meta:
    description = "takes screenshots from Python"

  strings:
    $PIL       = "PIL" fullword
    $ImageGrab = "ImageGrab" fullword
    $import    = "import" fullword

  condition:
    filesize < 1MB and all of them
}

rule macos_screen_capture {
  strings:
    $capture_screen = "captureScreen"
    $cg_window      = "CGWindowListCreateImageFromArray"
    $not_private    = "/System/Library/PrivateFrameworks"
    $not_nuclei     = "projectdiscovery"
    $not_microsoft  = "Microsoft Corporation"

  condition:
    1 of ($c*) and none of ($not*)
}
