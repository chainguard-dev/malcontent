rule macos_setApp {
  strings:
    $setApp = "setApp:for"
    $sda    = "setting default application"

  condition:
    any of them
}
