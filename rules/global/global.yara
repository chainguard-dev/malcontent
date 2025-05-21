import "elf"

private rule global_binary {
  condition:
    filesize < 40MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

private rule global_bundled_glibc {
  meta:
    description = "includes bundled copy of glibc"
    filetypes   = "elf,so"

  strings:
    $glibc_private  = "GLIBC_PRIVATE"
    $glibc_tunables = "GLIBC_TUNABLES"
    $setup_vdso     = "setup_vdso"

  condition:
    filesize > 1024 and filesize < 25MB and elf.type == elf.ET_EXEC and uint32(0) == 1179403647 and all of them
}

private rule global_bundled_openssl {
  meta:
    description = "includes bundled copy of OpenSSL"
    filetypes   = "elf,so"

  strings:
    $ref        = "OpenSSL/"
    $aes_part   = "AES part of OpenSSL"
    $montgomery = "Montgomery Multiplication for x86_64, CRYPTOGAMS"
    $rc4        = "RC4 for x86_64, CRYPTOGAMS"

  condition:
    filesize > 1024 and filesize < 150MB and elf.type == elf.ET_EXEC and uint32(0) == 1179403647 and any of them
}

private rule global_container_managers {
  strings:
    $containerd = "github.com/containerd/containerd"
    $systemd    = "SYSTEMD_PROC_CMDLINE"
    $snapd      = "snapcore/snapd"

  condition:
    any of them
}

private rule global_elf_or_macho {
  condition:
    uint32(0) == 1179403647 or (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178)
}

private rule global_exfil {
  strings:
    $f_app_json = "application/json"
    $f_post     = "requests.post"
    $f_nsurl    = "NSURLRequest"
    $f_curl     = /curl.{0,32}-X POST/

    $not_requests_utils = "requests.utils"

  condition:
    filesize < 512KB and any of ($f*) and none of ($not*)
}

private rule global_iplookup_website {
  meta:
    description = "public service to discover external IP address"

  strings:
    $ipify       = "ipify.org"
    $wtfismyip   = "wtfismyip"
    $iplogger    = "iplogger.org"
    $getjsonip   = "getjsonip"
    $ipconfig_me = "ifconfig.me"
    $icanhazip   = "icanhazip"
    $ident_me    = "ident.me" fullword
    $showip_net  = "showip.net" fullword
    $ifconfig_io = "ifconfig.io" fullword
    $ifconfig_co = "ifconfig.co" fullword
    $ipinfo      = "ipinfo.io"
    $ipify_b     = "ipify.org" base64
    $wtfismyip_b = "wtfismyip" base64
    $iplogger_b  = "iplogger.org" base64
    $getjsonip_b = "getjsonip" base64
    $ipinfo_b    = "ipinfo.io" base64
    $ipify_x     = "ipify.org" xor(1-255)
    $wtfismyip_x = "wtfismyip" xor(1-255)
    $iplogger_x  = "iplogger.org" xor(1-255)
    $getjsonip_x = "getjsonip" xor(1-255)
    $ipinfo_x    = "ipinfo.io" xor(1-255)

    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 250MB and any of them and none of ($not*)
}

private rule global_legal_license {
  strings:
    $ = "using, exploiting or modifying the Software"
    $ = "exploit the Information commercially"
    $ = "otherwise exploited by anyone for any purpose"

  condition:
    any of them
}

private rule global_local_cd {
  strings:
    $cd = /cd [a-z]{4,12}; \.\//

  condition:
    any of them
}

private rule global_macho {
  condition:
    (uint32(0) == 4277009102
      or uint32(0) == 3472551422
      or uint32(0) == 4277009103
      or uint32(0) == 3489328638
      or uint32(0) == 3405691582
      or uint32(0) == 3199925962
      or uint32(0) == 3405691583
      or uint32(0) == 3216703178)
}

private rule global_normal_elf {
  condition:
    filesize < 64MB and uint32(0) == 1179403647
}

private rule global_obfuscate {
  strings:
    $b64decode = "b64decode"
    $base64    = "base64"
    $codecs    = "codecs.decode"
    $x_decode  = /\w{0,16}XorDecode[\w]{0,32}/
    $x_encode  = /\w{0,16}XorEncode[\w]{0,32}/
    $x_file    = /\w{0,16}XorFile[\w]{0,32}/
    $x_decode_ = /\w{0,16}xor_decode[\w]{0,32}/
    $x_encode_ = /\w{0,16}xor_encode[\w]{0,32}/
    $x_file_   = /\w{0,16}xor_file[\w]{0,32}/

  condition:
    filesize < 512KB and any of them
}

private rule global_package_scripts {
  strings:
    $npm_name        = /"name":/
    $npm_version     = /"version":/
    $npm_description = /"description":/
    $npm_lint        = /"lint":/
    $npm_test        = /"test":/
    $npm_postversion = /"postversion":/
    $npm_postinstall = /"postinstall":/
    $scripts         = /"scripts":/

  condition:
    filesize < 32KB and 3 of ($npm*) and $scripts
}

private rule global_post_json {
  strings:
    $json             = "application/json"
    $POST             = "POST"
    $encode_stringify = "JSON.stringify"

  condition:
    $json and $POST and any of ($encode*)
}

private rule global_py_fetcher {
  meta:
    description = "fetches content"
    filetypes   = "py"

  strings:
    $http_requests      = "requests.get" fullword
    $http_requests_post = "requests.post" fullword
    $http_urllib        = "urllib.request" fullword
    $http_urlopen       = "urlopen" fullword
    $git_git            = /git.Git\(.{0,64}/
    $http_curl          = "curl" fullword
    $http_wget          = "wget" fullword

  condition:
    any of them
}

private rule global_py_runner {
  meta:
    description = "runs programs"
    filetypes   = "py"

  strings:
    $os_system    = /os.system\([\"\'\w\ \-\)\/]{0,64}/
    $os_startfile = /os.startfile\([\"\'\w\ \-\)\/]{0,64}/
    $os_popen     = /os.spopen\([\"\'\w\ \-\)\/]{0,64}/
    $subprocess   = /subprocess.\w{1,32}\([\"\'\/\w\ \-\)]{0,64}/
    $system       = /system\([\"\'\w\ \-\)\/]{0,64}/

  condition:
    any of them
}

private rule global_python_setup {
  meta:
    filetypes = "py"

  strings:
    $if_distutils  = /from distutils.core import .{0,32}setup/
    $if_setuptools = /from setuptools import .{0,32}setup/
    $i_setuptools  = "import setuptools"
    $setup         = "setup("

    $not_setup_example = ">>> setup("
    $not_setup_todict  = "setup(**config.todict()"
    $not_import_quoted = "\"from setuptools import setup"
    $not_setup_quoted  = "\"setup(name="
    $not_distutils     = "from distutils.errors import"
    $not_numba         = "https://github.com/numba/numba"

    $not_hopper1 = "PACKAGE_NAME = \"flashattn-hopper\""
    $not_hopper2 = "check_if_cuda_home_none(\"--fahopper\")"
    $not_hopper3 = "name=\"flashattn_hopper_cuda\","

  condition:
    filesize < 131072 and $setup and any of ($i*) and none of ($not*)
}

private rule global_sensitive_log_files {
  strings:
    $wtmp     = "/var/log/wtmp"
    $secure   = "/var/log/secure"
    $cron     = "/var/log/cron"
    $iptables = "/var/log/iptables.log"
    $auth     = "/var/log/auth.log"
    $cron_log = "/var/log/cron.log"
    $httpd    = "/var/log/httpd"
    $syslog   = "/var/log/syslog"
    $btmp     = "/var/log/btmp"
    $lastlog  = "/var/log/lastlog"
    $run_log  = "/run/log/"
    $mail_log = "/var/spool/mail/root"

  condition:
    filesize < 16KB and 2 of them
}

private rule global_small_binary {
  condition:
    filesize < 10MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

private rule global_small_elf {
  condition:
    filesize < 400KB and uint32(0) == 1179403647
}

private rule global_small_elf_or_macho {
  condition:
    filesize > 1MB and filesize < 8MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

private rule global_small_macho {
  condition:
    filesize < 64MB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

private rule global_specific_macho {
  strings:
    $not_jar   = "META-INF/"
    $not_dwarf = "_DWARF"
    $not_kext  = "_.SYMDEF SORTED"

  condition:
    (uint32(0) == 4277009102
      or uint32(0) == 3472551422
      or uint32(0) == 4277009103
      or uint32(0) == 3489328638
      or uint32(0) == 3405691582
      or uint32(0) == 3199925962
      or uint32(0) == 3405691583
      or uint32(0) == 3216703178)
    and none of ($not*)
}

private rule global_stub_macho {
  strings:
    $stub_helper = "__stub_helper"

  condition:
    filesize < 1MB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $stub_helper
}

private rule global_ufw_tool {
  strings:
    $not_route         = "route-insert"
    $not_statusverbose = "statusverbose"
    $not_enables_the   = "enables the"
    $not_enable_the    = "enable the"
    $not_enable        = "ufw enable"

  condition:
    filesize < 256KB and any of them
}

private rule global_word_list {
  strings:
    $scorpion = "scorpion"
    $superman = "superman"
    $porsche  = "porsche"
    $cardinal = "cardinal"
    $wombat   = "wombat"

  condition:
    filesize < 100MB and 3 of them
}
