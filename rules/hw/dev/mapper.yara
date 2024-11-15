rule dev_mapper: medium linux {
  meta:
    description = "uses the device mapper framework"
    ref         = "https://en.wikipedia.org/wiki/Device_mapper"

  strings:
    $val = /\/dev\/mapper[\$\%\w\{\}]{0,16}/

  condition:
    any of them
}
