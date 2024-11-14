rule dev_mapper: medium linux {
  meta:
    description           = "uses the device mapper framework"
    ref                   = "https://en.wikipedia.org/wiki/Device_mapper"

    hash_2023_rc_d        = "30b0e00414ce76f7f64175fb133632d5c517394bc013b0efe3d8ead384d5e464"

  strings:
    $val = /\/dev\/mapper[\$\%\w\{\}]{0,16}/

  condition:
    any of them
}
