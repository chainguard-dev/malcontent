rule dial_shared_screen_discovery: high {
  meta:
    description = "connects to remote screen using dial protocol"

  strings:
    $urn_multiscreen = "urn:dial-multiscreen-org:service:dial:1"
    $not_chromium    = "RasterCHROMIUM"

  condition:
    $urn_multiscreen and none of ($not*)
}
