rule os_ref: low {
  meta:
    description = "references a specific operating system"

  strings:
    $http  = "http://"
    $https = "https://"

    $o_macOS   = "macOS"
    $o_Darwin  = "Darwin"
    $o_Linux   = "Linux"
    $o_Windows = "Windows"
    $o_linux   = "linux"
    $o_darwin  = "darwin"
    $o_windows = "windows"

  condition:
    any of ($http*) and any of ($o*)
}

rule multiple_os_ref: medium {
  meta:
    description = "references multiple operating systems"

  strings:
    $http  = "http://"
    $https = "https://"

    $O_macOS   = "macOS"
    $O_Darwin  = "Darwin"
    $O_Linux   = "Linux"
    $O_Windows = "Windows"
    $o_linux   = "linux"
    $o_darwin  = "darwin"
    $o_windows = "windows"
    $o_macos   = "macos"

  condition:
    any of ($http*) and (2 of ($o*) or 2 of ($O*))
}
