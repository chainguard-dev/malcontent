rule macos_webcam_user: medium {
  meta:
    description = "accesses webcam"

  strings:
    $device_list = "SGGetChannelDeviceList"
    $set_channel = "SGSetChannelDevice"
    $cv2         = "cv2.VideoCapture"

  condition:
    any of them
}
