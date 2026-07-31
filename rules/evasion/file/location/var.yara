rule var_hidden: high {
  meta:
    description = "path reference to hidden file within /var"

  strings:
    $ref = /\/var\/\.[%\w\.\-\/]{0,64}/ fullword

    $not_updated = "/var/.updated" fullword

  condition:
    // $ref matches "/var/.updated" itself, so count past it: a file that only
    // names that stamp file stays quiet, one naming another hidden /var path fires
    $ref and #ref > #not_updated
}
