rule rename_requests: medium {
  meta:
    description                              = "imports 'requests' library and gives it another name"
    hash_2021_DiscordSafety_init             = "05c23917c682326179708a1d185ea88632d61522513f08d443bfd5c065612903"
    hash_2021_DiscordSafety_0_1_setup        = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"
    hash_2023_barcodegeneratorqr_1_0_3_setup = "ce066194bbf5c80c2ebe98ad20db41cf35d2fc4faf370a60ff2b129a836443a9"

  strings:
    $ref = /import requests as \w{0,64}/

  condition:
    filesize < 512KB and all of them
}

rule rename_requests_2char: high {
  meta:
    description                              = "imports 'requests' library and gives it a two-letter name"
    hash_2021_DiscordSafety_init             = "05c23917c682326179708a1d185ea88632d61522513f08d443bfd5c065612903"
    hash_2021_DiscordSafety_0_1_setup        = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"
    hash_2023_barcodegeneratorqr_1_0_3_setup = "ce066194bbf5c80c2ebe98ad20db41cf35d2fc4faf370a60ff2b129a836443a9"

  strings:
    $ref = /import requests as \w{2}/

  condition:
    filesize < 65535 and all of them
}

rule rename_os: high {
  meta:
    description = "imports 'os' library and gives it another name"

  strings:
    $ref            = /import os as \w{0,64}/
    $not_underscore = "import os as _os"
    $not_gos        = "import os as gos"

  condition:
    filesize < 65535 and $ref and none of ($not*)
}

rule rename_marshal: critical {
  meta:
    description                       = "imports 'marshal' library and gives it another name"
    hash_2021_DiscordSafety_init      = "05c23917c682326179708a1d185ea88632d61522513f08d443bfd5c065612903"
    hash_2021_DiscordSafety_0_1_setup = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"

  strings:
    $ref = /import marshal as \w{0,64}/

  condition:
    filesize < 512KB and all of them
}

rule rename_base64: critical {
  meta:
    description                          = "imports 'base64' library and gives it another name"
    hash_2022_very_hackerman_0_0_1_setup = "66a4a39a3c79a24bdf150cb87106920442a3db20a59810eb3e06149b028c7bff"
    hash_2022_example_package_init       = "5c0db191458fe648d6799d1461d20e79e65986ba6db522db3737ebbf99c577cb"
    hash_2022_xoloaghvurilnh_init        = "87a23edfa8fbcc13d1a25b9ac808dbc36c417fda508f98186455a7991a52b6c0"

  strings:
    $ref = /import base64 as \w{0,64}/

  condition:
    filesize < 1MB and all of them
}

rule rename_zlib: high {
  meta:
    description                          = "imports 'base64' library and gives it another name"
    hash_2022_very_hackerman_0_0_1_setup = "66a4a39a3c79a24bdf150cb87106920442a3db20a59810eb3e06149b028c7bff"
    hash_2022_example_package_init       = "5c0db191458fe648d6799d1461d20e79e65986ba6db522db3737ebbf99c577cb"
    hash_2022_xoloaghvurilnh_init        = "87a23edfa8fbcc13d1a25b9ac808dbc36c417fda508f98186455a7991a52b6c0"

  strings:
    $ref = /import zlib as \w{0,64}/

  condition:
    filesize < 512KB and all of them
}
