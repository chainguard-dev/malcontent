rule mm_client_js_map: override {
  meta:
    description        = "3937.844b09f50594ca2613b4.js"
    casing_obfuscation = "medium"

  strings:
    $mattermost = "mattermost"
    $powershell = "PowerShell"

  condition:
    filesize < 20KB and all of them
}
