
rule xz_command : medium {
  meta:
    description = "command shells out to xz"
    hash_2023_Linux_Malware_Samples_ac5a = "ac5a59554e033f3e513d21ab67872dbe4082eed6255d8302cb912d637751d22e"
  strings:
    $ref = "xz -"
  condition:
    $ref
}

rule xz_lib : medium {
  meta:
    description = "uses xz library"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
  strings:
    $ref = "ulikunitz/xz"
  condition:
    $ref
}
