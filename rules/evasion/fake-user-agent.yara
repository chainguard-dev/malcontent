
rule fake_user_agent_msie : suspicious {
  strings:
    $u_msie = "compatible; MSIE"
    $u_msie2 = "MSIE 9.0"
	$not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_khtml : suspicious {
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
