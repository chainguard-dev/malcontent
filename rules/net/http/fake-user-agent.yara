rule fake_user_agent_msie: high {
  meta:
    description = "pretends to be MSIE"

  strings:
    $u_MSIE         = /compatible; MSIE[ \;\(\)\w]{0,32}/
    $u_msie         = /compatible; msie[ \;\(\)\w]{0,32}/
    $u_msie2        = /MSIE 9.0\{/
    $not_access_log = "\"GET http://"
    $not_pixel      = "Pixel 5"
    $not_ipad       = "iPad Mini"
    $not_firefox    = "Firefox"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_windows_user_agent: high {
  meta:
    description = "pretends to be a Windows browser"

  strings:
    $u_Win64        = /Windows NT 10.0; Win64/
    $u_WinNT        = /Mozilla\/5.0 \(Windows NT/
    $not_access_log = "\"GET http://"
    $not_pixel      = "Pixel 5"
    $not_ipad       = "iPad Mini"
    $not_firefox    = "Firefox"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_khtml_val: high {
  strings:
    $u_khtml        = /KHTML, like Gecko\w Version\/\d+.\d+ Safari/
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_chrome: medium {
  meta:
    description = "pretends to be Chrome"

  strings:
    $u_chrome       = "(KHTML, like Gecko) Chrome"
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_wordpress: high {
  strings:
    $u_wordpress    = "User-Agent: Internal Wordpress RPC connection"
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_firefox: medium {
  meta:
    description = "pretends to be Firefox"

  strings:
    $u_gecko        = "Gecko/20"
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_netscape {
  strings:
    $u_mozilla      = "Mozilla/4" fullword
    $not_access_log = "\"GET http://"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_curl {
  strings:
    $u_curl         = "User-Agent: curl/"
    $not_access_log = "\"GET http://"

  condition:
    any of ($u_*) and none of ($not_*)
}

rule elf_faker_val: medium {
  meta:
    description = "Fake user agent"

  strings:
    $val = /Mozilla\/5[\.\w ]{4,64}/

  condition:
    uint32(0) == 1179403647 and $val
}

rule lowercase_mozilla_val: high {
  meta:
    description = "Fake user agent"

  strings:
    $ref = /mozilla\/\d{1,2}\.[\.\w ]{0,32}/

  condition:
    $ref
}
