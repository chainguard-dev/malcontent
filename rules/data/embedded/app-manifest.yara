rule app_manifest: medium {
  meta:
    description = "Contains embedded Microsoft Windows application manifest"
    ref         = "https://learn.microsoft.com/en-us/cpp/build/reference/manifestuac-embeds-uac-information-in-manifest?view=msvc-170"

    hash_2023_Downloads_CF7               = "18195648d7dd6e5654785f57dd595f8a6de963571018aea172fe5b4d2b2a9fda"


  strings:
    $priv = "requestedPrivileges"
    $exec = "requestedExecutionLevel"

  condition:
    all of them
}
