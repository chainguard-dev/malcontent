
rule fake_user_agent_msie : suspicious {
  strings:
    $u_MSIE = "compatible; MSIE"
    $u_msie = "compatible; msie"
    $u_msie2 = "MSIE 9.0"
	$not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_khtml_val : suspicious {
  strings:
    $u_khtml = /KHTML, like Gecko\w Version\/\d+.\d+ Safari/
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
	$not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}


rule fake_user_agent_chrome : notable {
  strings:
    $u_chrome = "(KHTML, like Gecko) Chrome"
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
	$not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_wordpress : suspicious {
  strings:
    $u_wordpress = "User-Agent: Internal Wordpress RPC connection"
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
	$not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_firefox : notable {
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

rule elf_faker_val : high {
  meta:
	description = "Fake user agent inside ELF binary"
  strings:
	$ref = /Mozilla\/5[\.\w ]{0,32}/
  condition:
    uint32(0) == 1179403647 and $ref
}


rule lowercase_mozilla_val : suspicious {
  meta:
	description = "Fake user agent"
  strings:
	$ref = /mozilla\/\d{1,2}\.[\.\w ]{0,32}/
  condition:
	$ref
}
