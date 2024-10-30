rule bsd_time_conversion: harmless {
  strings:
    $asctime   = "asctime" fullword
    $ctime     = "ctime" fullword
    $difftime  = "difftime" fullword
    $gmtime    = "gmtime" fullword
    $localtime = "localtime" fullword
    $mktime    = "mktime" fullword
    $timegm    = "timegm" fullword

  condition:
    any of them
}
