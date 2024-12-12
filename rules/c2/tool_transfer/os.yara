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

  condition:
    any of ($http*) and any of ($o*)
}

rule multiple_os_ref: medium {
  meta:
    description = "references multiple operating systems"

  strings:
    $http  = "http://"
    $https = "https://"

    $o_macOS   = "macOS"
    $o_Darwin  = "Darwin"
    $o_Linux   = "Linux"
    $o_Windows = "Windows"

  condition:
    any of ($http*) and 2 of ($o*)
}
