rule en_us_utf8: medium {
  meta:
    description = "hardcodes language to American English"

  strings:
    $ = "en_US.UTF-8" fullword

  condition:
    any of them
}
