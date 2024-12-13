rule plugin_persist: high {
  meta:
    description = "may use persistence plugins"

  strings:
    $ref = "plugin_persist"

  condition:
    any of them
}
