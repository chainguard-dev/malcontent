rule dock_hider: high {
  meta:
    description = "hides application from Dock"

  strings:
    $hideDock            = "hideDock"
    $applicationWillHide = "applicationWillHide"

  condition:
    any of them
}
