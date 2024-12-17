rule semicolon_short_tmp: high {
  meta:
    description = "unusual one-liners involving /tmp"

  strings:
    $tmp_before = /[\w\/ \-\;]{0,32} \/tmp\/[a-z]{1,5} {0,2};/
    $tmp_after  = /[\w\/ \-]{0,32}; {0,2}\/tmp\/[a-z]{1,5}[\w\/ \-\&\;]{0,32}/

    $not_dashes = "--;/tmp"

  condition:
    filesize < 1MB and any of ($tmp*) and none of ($not*)
}

rule semicolon_short_var_tmp: high {
  meta:
    description = "unusual one-liners involving /var/tmp"

  strings:
    $var_tmp_before = /[\w\/ \-\;]{0,32} \/var\/tmp\/[a-z]{1,5} {0,2};/
    $var_tmp_after  = /[\w\/ \-]{0,32}; {0,2}\/var\/tmp\/[a-z]{1,5}[\w\/ \-\&\;]{0,32}/
    $not_dashes     = "--;/var/tmp"

  condition:
    filesize < 1MB and any of ($var*) and none of ($not*)

}
