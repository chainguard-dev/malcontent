
rule macos_webcam_user : pua {
  strings:
    $device_list = "SGGetChannelDeviceList"
    $set_channel = "SGSetChannelDevice"
  condition:
    any of them
}
