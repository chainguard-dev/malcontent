rule macos_webcam_user : pua {
  meta:
    hash_2014_wacaw_eleanor = "3aa88184ba93854538c37eaa630b5bafdd9b2eba155524d06d962d025ab00fac"
    hash_2017_Perl_FruitFly_A = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_2017_Perl_FruitFly_A_pentil = "302d359c329122f0e7638ac7d29af2d4d3f2980cb1256bd3c0f08a1671e079f0"
    hash_2017_FruitFly_A_a83f = "a83fbe4cffc9d931365a7dd5ea01b8b04df0ec69ac51a4cbb59907459a1a0936"
    hash_2017_Perl_FruitFly_quimitchin = "ce07d208a2d89b4e0134f5282d9df580960d5c81412965a6d1a0786b27e7f044"
  strings:
    $device_list = "SGGetChannelDeviceList"
    $set_channel = "SGSetChannelDevice"
  condition:
    any of them
}

