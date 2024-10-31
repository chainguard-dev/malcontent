
rule danger_compiled_osascript : medium {
  meta:
    hash_2023_Scripts_main = "7c66d2d75be43d2c17e75d37c39344a9b5d29ee5c5861f178aa7d9f34208eb48"
  strings:
    $s_sysoexec = "sysoexecTEXT"
    $s_aevtoapp = "aevtoappnull"
    $not_capture_one = "Capture One"
    $not_display_alert = "display alert"
    $not_saving = "saving"
    $not_captureone = "captureone"
  condition:
    filesize < 1048576 and all of ($s_*) and none of ($not*)
}
