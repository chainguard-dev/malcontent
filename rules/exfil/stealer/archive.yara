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

rule hardcoded_tmp_archive: high {
  meta:
    description = "references hard-coded zip file in temp directory"

  strings:
    $tmp_zip = /\/tmp\/[\.\w]{1,4}\.zip/

  condition:
    filesize < 25MB and any of them
}

rule ditto_crypto_stealer: high {
  meta:
    description = "makes HTTP connections and creates archives using ditto"

  strings:
    $http_POST = /POST[ \/\w]{0,32}/
    $w_ditto   = /ditto -[\w\-\/ ]{0,32}/
    $w_zip     = /[\%\@\w\-\/ ]{1,32}\.zip/

  condition:
    any of ($http*) and 2 of ($w*)
}

rule usbmon_webproxy_zipper: high {
  meta:
    description = "uses usbmon, web proxies, and zip files"

  strings:
    $usbmon         = "usbmon" fullword
    $webproxy       = "WebProxy"
    $web_proxy      = "webproxy"
    $zip            = "zip" fullword
    $not_pypi_index = "testpack-id-lb001"

  condition:
    $usbmon and $zip and any of ($web*) and none of ($not*)
}

rule osascript_http_zipper: high {
  meta:
    description = "runs AppleScript, makes HTTP requests, zips files"

  strings:
    $ref     = "osascript" fullword
    $readdir = "readdir" fullword
    $socket  = "socket" fullword
    $http    = "HTTP" fullword
    $zip     = "zip_writer"

  condition:
    all of them
}
