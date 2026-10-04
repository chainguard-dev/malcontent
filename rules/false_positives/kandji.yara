rule kandji: override {
  meta:
    description                 = "Kandji"
    hostinfo_collector_api      = "medium"
    hostinfo_collector_commands = "medium"

  strings:
    $ref = "Developer ID Application: Kandji, Inc. (P3FGV63VK7)"

  condition:
    any of them
}
