rule fake_user_agent_msie: high {
  meta:
    description = "pretends to be MSIE"

  strings:
    $u_MSIE         = /compatible; MSIE[ \;\(\)\w]{0,32}/
    $u_msie         = /compatible; msie[ \;\(\)\w]{0,32}/
    $u_msie2        = /MSIE 9.0{/
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
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"

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
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2024_Downloads_036a     = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

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
    description              = "Fake user agent"
    hash_2024_Downloads_fd0b = "fd0b5348bbfd013359f9651268ee67a265bce4e3a1cacf61956e3246bac482e8"

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
