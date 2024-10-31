
rule base64_http_val : high {
  meta:
    description = "base64 HTTP protocol references"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_pan_chan_6896 = "6896b02503c15ffa68e17404f1c97fd53ea7b53c336a7b8b34e7767f156a9cf2"
    hash_2023_pan_chan_73ed = "73ed0b692fda696efd5f8e33dc05210e54b17e4e4a39183c8462bcc5a3ba06cc"
  strings:
    $user_agent = "User-Agent" base64
    $mozilla_5_0 = "Mozilla/5.0" base64
    $referer = "Referer" base64
    $http_1_0 = "HTTP/1.0" base64
    $http_1_1 = "HTTP/1.1" base64
  condition:
    any of them
}
