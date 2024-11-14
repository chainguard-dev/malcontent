rule xor_url: high {
  meta:
    description = "URL hidden using XOR encryption"

  strings:
    $http        = "http:" xor(1-31)
    $https       = "https:" xor(1-31)
    $ftp         = "ftp:/" xor(1-31)
    $office      = "office" xor(1-31)
    $google      = "google." xor(1-31)
    $microsoft   = "microsoft" xor(1-31)
    $apple       = "apple." xor(1-31)
    $user_agent  = "User-Agent" xor(1-31)
    $http2       = "http://" xor(33-255)
    $https2      = "https://" xor(33-255)
    $ftp2        = "ftp://" xor(33-255)
    $google2     = "google." xor(33-255)
    $microsoft2  = "microsoft" xor(33-255)
    $apple2      = "apple." xor(33-255)
    $user_agent2 = "User-Agent" xor(33-255)

  condition:
    any of them
}
