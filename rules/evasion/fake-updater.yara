rule fake_chrome_update: high {
  meta:
    description = "May fake being a Chrome update"

  strings:
    $ref     = "GoogleChromeUpdate"
    $updater = "com.google.Chrome.UpdaterPrivilegedHelper"

  condition:
    $ref and not $updater
}
