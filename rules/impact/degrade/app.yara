rule osascript_window_closer: medium {
  meta:
    description = "closes the window of a running application"
    filetypes   = "scpt,scptd"

  strings:
    $c_osascript   = "osascript" fullword
    $c_tell        = "tell" fullword
    $c_application = "application" fullword
    $c_app_name    = /\"\w[\.\w]{3,24}\w\"/ fullword
    $c_to          = "to" fullword
    $c_close       = "close" fullword
    $c_window      = "window" fullword

  condition:
    filesize < 256KB and all of ($c*)
}

rule osascript_quitter: medium {
  meta:
    description = "quits a running application"
    filetypes   = "scpt,scptd"

  strings:
    $c_osascript   = "osascript" fullword
    $c_tell        = "tell" fullword
    $c_application = "application" fullword
    $c_app_name    = /\"\w[\.\w]{3,24}\w\"/ fullword
    $c_to          = "to" fullword
    $c_quit        = "quit" fullword

  condition:
    filesize < 256KB and all of ($c*)
}
