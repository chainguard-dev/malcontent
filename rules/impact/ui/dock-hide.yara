rule dock_hider: high {
  meta:
  strings:
    $hideDock            = "hideDock"
    $applicationWillHide = "applicationWillHide"

  condition:
    any of them
}
