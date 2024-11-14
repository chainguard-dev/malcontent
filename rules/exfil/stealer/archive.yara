rule open_and_archive: medium macos {
  meta:
    description = "can call /usr/bin/open and archiving tools"

  strings:
    $open         = "/usr/bin/open" fullword
    $defaults     = "/usr/bin/defaults"
    $tar          = "/usr/bin/tar"
    $zip          = "/usr/bin/zip"
    $not_private  = "/System/Library/PrivateFrameworks/"
    $not_keystone = "Keystone"
    $not_sparkle  = "org.sparkle-project.Sparkle"
    $hashbang     = "#!"

  condition:
    ($open or $defaults) and ($tar or $zip) and none of ($not*) and not $hashbang at 0
}
