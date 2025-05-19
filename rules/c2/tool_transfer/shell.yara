rule fetch_chmod_run_oneliner_value: critical {
  meta:
    description = "fetches, chmods, and runs a program"
    filetypes   = "bash,sh,zsh"

  strings:
    $ref = /[a-z](url|get) .{4,64}chmod .{4,64}\.\/[a-z]{1,16}/

  condition:
    any of them
}

rule tool_chmod_relative_run: medium {
  meta:
    description = "may fetch file, make it executable, and run it"
    filetypes   = "bash,sh,zsh"

  strings:
    $f_curl      = /(curl|wget) [\-\w \$\@\{\w\/\.\:]{0,96}/
    $f_chmod     = /chmod [\+\-\w \$\@\{\w\/\.]{0,64}/
    $f_dot_slash = /\.\/[a-z\$]{1,2}[a-z\.\/\- ]{0,32}/ fullword

    $not_comment_curl = "# curl "

  condition:
    filesize < 1MB and all of ($f*) and none of ($not*)
}

rule fetch_tar_run: high {
  meta:
    description = "fetches, extracts, and runs program"
    filetypes   = "bash,sh,zsh"

  strings:
    $fetch_tar_relative = /(curl|wget).{8,128}tar -{0,1}x.{8,96}[;& ]\.\/[a-z\$]{1,2}.{0,64}/

  condition:
    filesize < 1MB and any of them
}

rule tool_chmod_relative_run_tiny: high {
  meta:
    description = "fetch file, make it executable, and run it"
    filetypes   = "bash,sh,zsh"

  strings:
    $must_cd     = /cd {1,2}[\/\$][\w\/]{0,16}/
    $must_rm     = /rm -[rR]{0,1}f  {1,2}[\/\$][\w\/]{0,16}/
    $o_curl      = /(curl|wget) [\-\w \$\@\{\w\/\.\:]{0,96}/
    $o_chmod     = /chmod [\+\-\w \$\@\{\w\/\.]{0,64}/
    $o_dot_slash = /\.\/[\$a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword

  condition:
    filesize < 6KB and any of ($must*) and all of ($o*)
}

rule helm_test_env: override {
  meta:
    description                  = "helm_test_env"
    tool_chmod_relative_run_tiny = "medium"
    filetypes                    = "application/x-sh,application/x-zsh"

  strings:
    $helm_curl = "curl -L https://get.helm.sh"

  condition:
    $helm_curl
}

rule tool_tor_chmod_relative_run: high {
  meta:
    description = "change dir, fetch file via tor, make it executable, and run it"
    filetypes   = "bash,sh,zsh"

  strings:
    $tor2web   = "tor2web"
    $tor2socks = "tor2socks"
    $tor_onion = ".onion"

    $cd        = /cd {1,2}[\/\$][\w\/]{0,16}/
    $curl      = /(curl|wget) [\-\w \$\@\{\w\/\.\:]{0,96}/
    $chmod     = /chmod [\+\-\w \$\@\{\w\/\.]{0,64}/
    $dot_slash = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword

    $not_go = "listen.onionndots"

  condition:
    filesize < 10MB and any of ($tor*) and $cd and $curl and $chmod and $dot_slash and filesize < 1MB and none of ($not*)
}

rule dev_null_rm: medium {
  meta:
    filetypes = "application/x-sh,application/x-zsh"

  strings:
    $dev_null_rm = /[ \w\.\/\&\-%]{0,32}\/dev\/null\;rm[ \w\/\&\.\-\%]{0,32}/

  condition:
    filesize < 20MB and any of them
}

rule sleep_rm: medium {
  meta:
    filetypes = "application/x-sh,application/x-zsh"

  strings:
    $dev_null_rm = /sleep;rm[ \w\/\&\.\-\%]{0,32}/

  condition:
    filesize < 1MB and any of them
}

rule nohup_bash_background: high {
  meta:
    filetypes = "application/x-sh,application/x-zsh"

  strings:
    $ref = /nohup bash [\%\w\/\\>]{0,64} &/

  condition:
    filesize < 1MB and any of them
}

rule fetch_pipe_shell_value: medium {
  meta:
    description = "fetches content and pipes it to a shell"
    filetypes   = "bash,sh,zsh"

  strings:
    $wget_bash = /wget .{8,128}\| {0,2}bash/
    $wget_sh   = /wget .{8,128}\| {0,2}sh/
    $curl_bash = /curl .{8,128}\| {0,2}bash/
    $curl_sh   = /curl .{8,128}\| {0,2}sh/

  condition:
    filesize < 1MB and any of them
}

rule fetch_chmod_execute: high {
  meta:
    description = "single line fetch, chmod, execute"
    filetypes   = "bash,sh,zsh"

  strings:
    $wget = /wget .{8,64} \&\&.{0,64} chmod .{3,16} \&\& \.\/[\.\w]{1,16}/
    $curl = /curl .{8,64} \&\&.{0,64} chmod .{3,16} \&\& \.\/[\.\w]{1,16}/

  condition:
    filesize < 20MB and any of them
}

rule possible_dropper: high {
  meta:
    description = "download and execute a program"
    filetypes   = "bash,sh,zsh"

  strings:
    $http          = /https{0,1}:\/\/[\.\w\/\?\=\-]{1,64}/
    $tool_curl_o   = /(curl|wget) [\w\.\- :\"\/]{0,64}-\w{0,2}[oO][\w\.\- :\"\/]{0,64}/
    $tool_lwp      = "lwp-download"
    $cmd_bash      = "bash" fullword
    $cmd_dot_slash = /\.\/[\.\w]{1,16}/ fullword
    $cmd_rm        = "rm" fullword
    $cmd_sleep     = "sleep" fullword
    $cmd_echo      = "echo" fullword
    $chmod         = "chmod" fullword

  condition:
    filesize < 1KB and any of ($http*) and $chmod and any of ($tool*) and any of ($cmd*)
}

rule nohup_dropper: critical {
  meta:
    description = "downloads and executes a program with nohup"
    filetypes   = "bash,sh,zsh"

  strings:
    $nohup = "nohup" fullword

  condition:
    possible_dropper and $nohup
}

rule obsessive_dropper: high {
  meta:
    description = "invokes multiple tools to download and execute a program"
    filetypes   = "bash,sh,zsh"

  strings:
    $http          = "http://"
    $https         = "https://"
    $tool_curl_s   = "curl -"
    $tool_wget_q   = "wget" fullword
    $tool_lwp      = "lwp-download" fullword
    $tool_tftp     = "tftp" fullword
    $cmd_bash      = "bash" fullword
    $cmd_dot_slash = /\.\/[\.\w]{1,16}/ fullword
    $cmd_rm        = "rm" fullword
    $cmd_sleep     = "sleep" fullword
    $cmd_echo      = "echo" fullword
    $cmd_chmod     = "chmod" fullword

  condition:
    filesize < 1500 and any of ($http*) and 2 of ($tool*) and any of ($cmd*)
}
