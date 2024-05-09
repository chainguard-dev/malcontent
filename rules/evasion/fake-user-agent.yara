
rule fake_user_agent_msie : high {
  meta:
    description = "pretends to be MSIE"
    hash_2023_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2023_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
    hash_2023_Chaos_27cd = "27cdb8d8f64ce395795fdbde10cf3a08e7b217c92b7af89cde22abbf951b9e99"
  strings:
    $u_MSIE = /compatible; MSIE[ \;\(\)\w]{0,32}/
    $u_msie = /compatible; msie[ \;\(\)\w]{0,32}/
    $u_msie2 = /MSIE 9.0{/
    $not_access_log = "\"GET http://"
    $not_pixel = "Pixel 5"
    $not_ipad = "iPad Mini"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_khtml_val : high {
  strings:
    $u_khtml = /KHTML, like Gecko\w Version\/\d+.\d+ Safari/
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_chrome : medium {
  meta:
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
  strings:
    $u_chrome = "(KHTML, like Gecko) Chrome"
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_wordpress : high {
  strings:
    $u_wordpress = "User-Agent: Internal Wordpress RPC connection"
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_firefox : medium {
  meta:
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
  strings:
    $u_gecko = "Gecko/20"
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_netscape {
  strings:
    $u_mozilla = "Mozilla/4" fullword
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_curl {
  strings:
    $u_curl = "User-Agent: curl/"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule elf_faker_val : medium {
  meta:
    description = "Fake user agent"
    hash_2024_Downloads_fd0b = "fd0b5348bbfd013359f9651268ee67a265bce4e3a1cacf61956e3246bac482e8"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2023_Linux_Malware_Samples_16bb = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
  strings:
    $val = /Mozilla\/5[\.\w ]{4,64}/
  condition:
    uint32(0) == 1179403647 and $val
}

rule lowercase_mozilla_val : high {
  meta:
    description = "Fake user agent"
    hash_2023_rustbucket_example = "c54bfacc63cd61c7d66e7282f17402c851b2b4cfdc9af7c1a81ad6a7838df19a"
  strings:
    $ref = /mozilla\/\d{1,2}\.[\.\w ]{0,32}/
  condition:
    $ref
}
