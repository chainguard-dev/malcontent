rule browser_extensions: medium {
  meta:
    description = "access Browser extensions"

  strings:
    $b_firefoxExtension = "Firefox/extensions"
    $b_safariExtension  = "Safari/Extensions"
    $b_installChrome    = "installChrome"
    $b_installFirefox   = "installFirefox"
    $b_installSafari    = "installSafari"
    $c_chromeExtension  = "/Extensions"
    $c_googleChrome     = "Google/Chrome"

  condition:
    any of ($b*) or all of ($c*)
}
