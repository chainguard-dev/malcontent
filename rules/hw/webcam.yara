rule macos_webcam_user: medium {
  meta:

  strings:
    $device_list = "SGGetChannelDeviceList"
    $set_channel = "SGSetChannelDevice"
    $cv2         = "cv2.VideoCapture"

  condition:
    any of them
}
