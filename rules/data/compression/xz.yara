
rule xz_command : medium {
  meta:
    description = "command shells out to xz"
    hash_2023_Linux_Malware_Samples_ac5a = "ac5a59554e033f3e513d21ab67872dbe4082eed6255d8302cb912d637751d22e"
    hash_2023_customizations_opsworks = "416dc4c8699bdb327d953e73a45dbe37d4bd8f1601bea16c30a43c398d937031"
    hash_2023_customizations_opsworks = "416dc4c8699bdb327d953e73a45dbe37d4bd8f1601bea16c30a43c398d937031"
  strings:
    $ref = "xz -"
  condition:
    $ref
}

rule xz_lib : medium {
  meta:
    description = "uses xz library"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2024_termite_termite_linux_amd64 = "fa8d2c01cf81a052ea46650418afa358252ce6f9ce2eb65df3b3e3c7165f8d92"
    hash_2024_termite_termite_linux_arm = "d36b8cfef77149c64cb203e139657d5219527c7cf4fee45ca302d89b7ef851e6"
  strings:
    $ref = "ulikunitz/xz"
  condition:
    $ref
}
