rule macos_ioplatform_deviceid: medium {
  meta:
    description = "machine unique identifier"

  strings:
    $ref  = "IOPlatformUUID" fullword
    $ref2 = "DeviceIDInKeychain"

  condition:
    any of them
}
