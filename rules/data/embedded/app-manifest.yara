rule app_manifest: medium {
  meta:
    description                                                                          = "Contains embedded Microsoft Windows application manifest"
    ref                                                                                  = "https://learn.microsoft.com/en-us/cpp/build/reference/manifestuac-embeds-uac-information-in-manifest?view=msvc-170"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_CF7                                                              = "18195648d7dd6e5654785f57dd595f8a6de963571018aea172fe5b4d2b2a9fda"
    hash_2023_Downloads_Purchase_List_Xls                                                = "8838c8ec2ad1e7f3d9b4efcd3c0c2134507988c60915b2a2a6bf10eac2fb3cde"

  strings:
    $priv = "requestedPrivileges"
    $exec = "requestedExecutionLevel"

  condition:
    all of them
}
