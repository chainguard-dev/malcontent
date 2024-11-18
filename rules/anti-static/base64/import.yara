rule b64_as_int: critical {
  meta:
    description = "hides term 'base64' within an integer array"

  strings:
    $f_decode = "decode"
    $f_ord    = "ord"

    $ib = "98,"
    $ia = "97,"
    $is = "115,"
    $ie = "101,"
    $i6 = "54,"
    $i4 = "52"

  condition:
    any of ($f*) and all of ($i*) and @ia > @ib and @is > @ia and @ie > @is and @i6 > @ie and @i4 > @i6 and @i6 - @ib <= 48

}
