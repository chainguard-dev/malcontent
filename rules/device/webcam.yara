
rule macos_webcam_user : medium {
  meta:
    hash_2008_utilities_wacaw = "3aa88184ba93854538c37eaa630b5bafdd9b2eba155524d06d962d025ab00fac"
    hash_1980_FruitFly_A_205f = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_1980_FruitFly_A_302d = "302d359c329122f0e7638ac7d29af2d4d3f2980cb1256bd3c0f08a1671e079f0"
  strings:
    $device_list = "SGGetChannelDeviceList"
    $set_channel = "SGSetChannelDevice"
  condition:
    any of them
}
