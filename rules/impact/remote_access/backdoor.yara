private rule wordlist {
  strings:
    $scorpion = "scorpion"
    $superman = "superman"
    $porsche  = "porsche"
    $cardinal = "cardinal"
    $wombat   = "wombat"

  condition:
    filesize < 100MB and 3 of them
}

rule backdoor: medium {
  meta:
    description = "References a 'backdoor'"

  strings:
    $ref = /[\/a-zA-Z\-_ \']{0,16}[bB]ackdoor[\/a-zA-Z\-_ ]{0,48}/

    $not_vcpu    = "VCPUInfoBackdoor"
    $not_vmware  = "gGuestBackdoorOps"
    $not_comment = "# backdoor:"

  condition:
    filesize < 40MB and any of them and not wordlist and none of ($not*)
}

rule backdoor_shell: high {
  meta:
    description = "references a backdoor shell"

  strings:
    $ref = /[bB]ackdoor.{0,1}[sS]hell/

  condition:
    any of them
}

rule backdoor_likely: high {
  meta:
    description = "References a 'backdoor', uses sensitive Linux functions"

  strings:
    $backdoor                     = "backdoor" fullword
    $f_ld_preload                 = "LD_PRELOAD" fullword
    $f_icmp                       = "ICMP" fullword
    $f_preload                    = "/etc/ld.so.preload"
    $f_sshd                       = "sshd" fullword
    $f_readdir64                  = "readdir64" fullword
    $not_BackdoorChannel_Fallback = "BackdoorChannel_Fallback"
    $not_pypi_index               = "testpack-id-lb001"

  condition:
    filesize < 10MB and $backdoor and any of ($f*) and none of ($not*)
}

rule backdoor_high: high {
  meta:
    description = "suspicious backdoor reference"

  strings:
    $lower_prefix = /(hidden|hide|icmp|pam|ssh|sshd)[ _]backdoor/
    $lower_sufifx = /backdoor[_ ](task|process|up|method|user|shell|login|pass)/

    $not_falco_dev_null        = "/dev/null is a backdoor method"
    $not_falco_backdoor_insert = "backdoor method for inserting special events"

  condition:
    filesize < 10MB and any of ($lower*) and none of ($not*)
}

rule backdoor_caps: high {
  meta:
    description = "References a 'BACKDOOR'"

  strings:
    $ref2 = /[a-zA-Z\-_ \']{0,16}BACKDOOR[a-zA-Z\-_ ]{0,16}/ fullword

  condition:
    filesize < 40MB and any of them and not wordlist
}

rule backdoor_leet: critical {
  meta:
    description = "References a 'backd00r'"

  strings:
    $ref4 = /[a-zA-Z\-_ \']{0,16}[bB][a4]ckd00r[a-zA-Z\-_ ]{0,16}/

  condition:
    filesize < 100MB and any of them and not wordlist
}

rule commands: high {
  meta:
    description = "may accept backdoor commands"

  strings:
    $hide = "hide ok" fullword
    $show = "show ok" fullword
    $kill = "kill ok" fullword

  condition:
    all of them
}

private rule backdoor_small_macho {
  condition:
    filesize < 1MB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

rule macho_backdoor_libc_signature: high {
  meta:
    description = "executes libc functions common to backdoors"
    filetypes   = "macho"

  strings:
    $word_with_spaces = /[a-z]{2,16} [a-uxyz]{2,16}/ fullword
    $libc_call        = /@_[a-z]{3,12}/ fullword

    $f_connect      = "@_connect" fullword
    $f_fork         = "@_fork" fullword
    $f_fread        = "@_fread" fullword
    $f_getenv       = "@_getenv" fullword
    $f_inet_addr    = "@_inet_addr" fullword
    $f_mkdir        = "@_mkdir" fullword
    $f_open         = "@_open" fullword
    $f_opendir      = "@_opendir" fullword
    $f_popen        = "@_popen" fullword
    $f_pthread      = "@_pthread_create" fullword
    $f_read         = "@_read" fullword
    $f_readdir      = "@_readdir" fullword
    $f_recv         = "@_recv" fullword
    $f_send         = "@_send" fullword
    $f_setsid       = "@_setsid" fullword
    $f_signal       = "@_signal" fullword
    $f_socket       = "@_socket" fullword
    $f_stat         = "@_stat" fullword
    $f_strchr       = "@_strchr" fullword
    $f_strcmp       = "@_strcmp" fullword
    $f_strcpy       = "@_strcpy" fullword
    $f_strlen       = "@_strlen" fullword
    $f_strstr       = "@_strstr" fullword
    $f_strtok       = "@_strtok" fullword
    $f_write        = "@_write" fullword
    $not_gmon_start = "__gmon_start__"
    $not_usage      = "usage:" fullword
    $not_usage2     = "Usage:" fullword
    $not_USAGE      = "USAGE:" fullword
    $not_java       = "java/lang"

  condition:
    backdoor_small_macho and #word_with_spaces < 10 and #libc_call < 74 and 95 % of ($f*) and none of ($not*)
}

rule minecraft_load_fetch_class_backdoor: critical {
  meta:
    description = "likely minecraft backdoor"
    filetypes   = "jar,java"

  strings:
    $minecraft   = "minecraft"
    $replace     = "loadReplacementClass"
    $url         = /https*:\/\/\w{1}[\w\.\/\&]{8,64}/
    $classLoader = "ClassLoader"
    $write       = "write"

  condition:
    filesize < 2MB and all of them
}
