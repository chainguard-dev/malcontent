
rule fetch_chmod_run_oneliner_value : critical {
  meta:
    description = "fetches, chmods, and runs a program"
    hash_2023_Unix_Dropper_Mirai_0e91 = "0e91c06bb84630aba38e9c575576b46240aba40f36e6142c713c9d63a11ab4bb"
    hash_2023_Unix_Dropper_Mirai_4d50 = "4d50bee796cda760b949bb8918881b517f4af932406307014eaf77d8a9a342d0"
    hash_2023_Unix_Dropper_Mirai_56ca = "56ca15bdedf9751f282b24d868b426b76d3cbd7aecff5655b60449ef0d2ca5c8"
  strings:
    $ref = /[a-z](url|get) .{4,64}chmod .{4,64}\.\/[a-z]{1,16}/
  condition:
    any of them
}

rule curl_chmod_relative_run : medium {
  meta:
    description = "may fetch file, make it executable, and run it"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_df3b = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
  strings:
    $chmcurlod = /curl [\-\w \$\@\{\w\/\.\:]{0,96}/
    $chmod = /chmod [\-\w \$\@\{\w\/\.]{0,64}/
    $dot_slah = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
  condition:
    all of them
}

rule wget_chmod_relative_run : medium {
  meta:
    description = "may fetch file, make it executable, and run it"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_3059 = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
  strings:
    $chmcurlod = /wget [\-\w \$\@\{\w\/\.\:]{0,96}/
    $chmod = /chmod [\-\w \$\@\{\w\/\.]{0,64}/
    $dot_slah = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
  condition:
    all of them
}

rule dev_null_rm : medium {
  strings:
    $dev_null_rm = /[ \w\.\/\&\-%]{0,32}\/dev\/null\;rm[ \w\/\&\.\-\%]{0,32}/
  condition:
    any of them
}

rule sleep_rm : medium {
  strings:
    $dev_null_rm = /sleep;rm[ \w\/\&\.\-\%]{0,32}/
  condition:
    any of them
}

rule nohup_bash_background : high {
  strings:
    $ref = /nohup bash [\%\w\/\>]{0,64} &/
  condition:
    any of them
}

rule fetch_pipe_shell_value : high {
  meta:
    description = "fetches content and pipes it to a shell"
    hash_2023_OK_29c2 = "29c2f559a9494bce3d879aff8731a5d70a3789028055fd170c90965ce9cf0ea4"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
  strings:
    $wget_bash = /wget .{8,128}\| {0,2}bash/
    $wget_sh = /wget .{8,128}\| {0,2}sh/
    $curl_bash = /curl .{8,128}\| {0,2}bash/
    $curl_sh = /curl .{8,128}\| {0,2}sh/
  condition:
    any of them
}

rule fetch_chmod_execute : high {
	meta:
		description = "single line fetch, chmod, execute"
	strings:
		$wget = /wget .{8,64} \&\&.{0,64} chmod .{3,16} \&\& \.\/[\.\w]{1,16}/
		$curl = /curl .{8,64} \&\&.{0,64} chmod .{3,16} \&\& \.\/[\.\w]{1,16}/
	condition:
		any of them
}