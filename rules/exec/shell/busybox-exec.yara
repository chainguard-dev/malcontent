
rule busybox_runner : medium linux {
  meta:
    hash_2023_Unix_Dropper_Mirai_0e91 = "0e91c06bb84630aba38e9c575576b46240aba40f36e6142c713c9d63a11ab4bb"
    hash_2023_Unix_Dropper_Mirai_4d50 = "4d50bee796cda760b949bb8918881b517f4af932406307014eaf77d8a9a342d0"
    hash_2023_Unix_Dropper_Mirai_56ca = "56ca15bdedf9751f282b24d868b426b76d3cbd7aecff5655b60449ef0d2ca5c8"
  strings:
    $ref = /\/bin\/busybox \w{2,16}[ \/\w\.]{0,64}/
  condition:
    all of them
}

rule busybox_runner_high : high linux {
  meta:
    hash_2023_Unix_Dropper_Mirai_0e91 = "0e91c06bb84630aba38e9c575576b46240aba40f36e6142c713c9d63a11ab4bb"
    hash_2023_Unix_Dropper_Mirai_4d50 = "4d50bee796cda760b949bb8918881b517f4af932406307014eaf77d8a9a342d0"
    hash_2023_Unix_Dropper_Mirai_56ca = "56ca15bdedf9751f282b24d868b426b76d3cbd7aecff5655b60449ef0d2ca5c8"
  strings:
    $ref = /\/bin\/busybox \w{2,16}[ \/\w\.]{0,64}/
	$not_cgroup = "cgroup" fullword
	$not_container = "container" fullword
	$not_ixr = "busybox ixr"
  condition:
    filesize < 256KB and $ref and none of ($not*)
}
