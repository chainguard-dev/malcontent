rule automator_launcher {
  strings:
    $automator = "/System/Library/CoreServices/Automator Launcher.app"
    $applet    = "com.apple.automator.applet"

  condition:
    filesize < 2097152 and all of them
}
