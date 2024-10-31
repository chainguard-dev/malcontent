import "math"

rule eval_base64 : high {
  meta:
    hash_2023_0xShell = "acf556b26bb0eb193e68a3863662d9707cbf827d84c34fbc8c19d09b8ea811a1"
    hash_2023_0xShell_0xObs = "6391e05c8afc30de1e7980dda872547620754ce55c36da15d4aefae2648a36e5"
    hash_2023_0xShell = "a6f1f9c9180cb77952398e719e4ef083ccac1e54c5242ea2bc6fe63e6ab4bb29"
  strings:
    $eval = /eval\(.{0,64}base64/
  condition:
    any of them
}

rule ruby_eval_base64_decode : critical {
  meta:
    description = "Evaluates base64 content"
    hash_2023_1_1_6_payload = "cbe882505708c72bc468264af4ef5ae5de1b75de1f83bba4073f91568d9d20a1"
    hash_2023_0_0_7_payload = "bb6ca6bfd157c39f4ec27589499d3baaa9d1b570e622722cb9bddfff25127ac9"
  strings:
    $eval_base64_decode = "eval(Base64."
  condition:
    any of them
}

rule ruby_eval_near_enough : critical {
  meta:
    description = "Evaluates base64 content"
    hash_2019_active_controller_middleware = "9a85e7aee672b1258b3d4606f700497d351dd1e1117ceb0e818bfea7922b9a96"
    hash_2023_1_1_6_payload = "cbe882505708c72bc468264af4ef5ae5de1b75de1f83bba4073f91568d9d20a1"
    hash_2023_0_0_7_payload = "bb6ca6bfd157c39f4ec27589499d3baaa9d1b570e622722cb9bddfff25127ac9"
  strings:
    $eval = "eval("
    $base64 = "Base64"
  condition:
    all of them and math.abs(@base64 - @eval) <= 128
}

rule ruby_eval2_near_enough : critical {
  meta:
    description = "Evaluates base64 content"
    hash_2023_siamttview = "7a19eb7e34f500af708eeccbf990ce623f58293e693a86bc1a99cc3bf18d1529"
  strings:
    $eval = "eval("
    $base64 = "b64decode"
  condition:
    all of them and math.abs(@base64 - @eval) <= 64
}

rule python_exec_near_enough : critical {
  meta:
    description = "Evaluates base64 content"
    hash_2023_UPX_7f5fd8c7cad4873993468c0c0a4cabdd8540fd6c2679351f58580524c1bfd0af_elf_x86_64 = "3b9f8c159df5d342213ed7bd5bc6e07bb103a055f4ac90ddb4b981957cd0ab53"
    hash_2019_CookieMiner_OAZG = "27ccebdda20264b93a37103f3076f6678c3446a2c2bfd8a73111dbc8c7eeeb71"
    hash_2018_EvilOSX_89e5 = "89e5b8208daf85f549d9b7df8e2a062e47f15a5b08462a4224f73c0a6223972a"
  strings:
    $exec = "exec("
    $base64 = "b64decode"
  condition:
    all of them and math.abs(@base64 - @exec) < 128
}

rule echo_decode_bash_probable : high {
  meta:
    description = "likely pipes base64 into a shell"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
    hash_2023_Unix_Trojan_Coinminer_3a6b = "3a6b3552ffac13aa70e24fef72b69f683ac221105415efb294fb9a2fc81c260a"
  strings:
    $echo = "echo" fullword
    $base64_decode = "base64 --decode"
    $base64_d = "base64 -d"
    $bash = "bash" fullword
    $sh = "sh" fullword
    $not_uucp = "UUCP" fullword
    $not_git = "git-core"
    $not_copyright = "Copyright (c)"
    $not_syntax = "syntax file"
  condition:
    filesize < 15KB and $echo and ($bash or $sh) and ($base64_decode or $base64_d) and none of ($not*)
}

rule acme_sh : override {
	meta:
		description = "acme.sh"
		echo_decode_bash_probable = "medium"
		iplookup_website = "medium"
	strings:
		$ref = "https://github.com/acmesh-official"
	condition:
		$ref
}

rule echo_decode_bash : critical { 
	meta:
		description = "executes base64 encoded shell commands"
	strings:
		$bash = /[\w=\$]{0,8} ?\| ?base64 -d[ecod]{0,5} ?\| ?bash/
		$sh = /[\w=\$]{0,8} ?\| ?base64 -d[ecod]{0,5} ?\| ?z?sh/
	condition:
		filesize < 64KB and any of them
}