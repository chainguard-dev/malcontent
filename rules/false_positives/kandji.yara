rule kandji: override {
  meta:
    description        = "Kandji"
    hostinfo_collector = "medium"

  strings:
    $ref = "Developer ID Application: Kandji, Inc. (P3FGV63VK7)"

  condition:
    any of them
}

