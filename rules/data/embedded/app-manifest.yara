rule app_manifest: medium {
  meta:
    description = "Contains embedded Microsoft Windows application manifest"
    ref         = "https://learn.microsoft.com/en-us/cpp/build/reference/manifestuac-embeds-uac-information-in-manifest?view=msvc-170"

  strings:
    $priv = "requestedPrivileges"
    $exec = "requestedExecutionLevel"

  condition:
    all of them
}
