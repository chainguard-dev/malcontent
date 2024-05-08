
rule dock_hider {
  strings:
    $hideDock = "hideDock"
  condition:
    any of them
}
