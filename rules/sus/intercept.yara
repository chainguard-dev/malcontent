rule interceptor: medium {
  meta:
    description                          = "References interception"
    hash_2023_Downloads_016a             = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_Brawl_Earth      = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Linux_Malware_Samples_6734 = "6734f3e911fadf340fc0aa4f8f55c15c8936c61f9b0e38bdfe9dde561cf09fa9"

  strings:
    $ref = /intercept[\w\_]{0,64}/ fullword

  condition:
    any of them
}
