rule php_possible_backdoor: critical {
  meta:
    description = "Decodes and evaluates code"

  strings:
    $php             = "<?php"
    $php_or          = "<? "
    $f_base64_decode = "base64_decode"
    $f_strrev        = "strrev"
    $f_rot13         = "str_rot13"
    $f_explode       = "explode"
    $f_preg          = "preg_replace"
    $f_serialize     = "serialize"
    $f_gzinflate     = "gzinflate"
    $f_remote_addr   = "REMOTE_ADDR"
    $f_exec          = "exec("
    $eval            = "eval"
    $not_aprutil     = "APR-UTIL"
    $not_highlight   = "Please see https://github.com/highlightjs/highlight.js/pull/"
    $not_javadoc     = "@param int"
    $not_php_group   = "Copyright (c) The PHP Group"
    $not_reference   = "stream_register_wrapper"
    $not_syntax      = "syntax file"
    $not_workaround  = "/* workaround for chrome bug "

  condition:
    filesize < 64KB and $eval and 1 of ($php*) and 4 of ($f_*) and none of ($not*)
}

rule php_eval_base64_decode: critical {
  meta:
    description = "directly evaluates base64 content"

  strings:
    $eval_base64_decode = "eval(base64_decode"

  condition:
    any of them
}

rule php_executor: critical {
  meta:
    description = "calls shell_exec and get_current_user"

  strings:
    $php          = "<?php"
    $f_shell_exec = "shell_exec("
    $f_user       = "get_current_user("

  condition:
    filesize < 1048576 and $php and all of ($f_*)
}

rule php_bin_hashbang: critical {
  meta:
    description = "PHP code that references hash-bangs and remotely supplied content"

  strings:
    $php     = "<?php"
    $script  = "#!/bin/"
    $post    = "$_POST" fullword
    $get     = "$_GET" fullword
    $not_php = "PHP_VERSION_ID"

  condition:
    filesize < 64KB and $php and $script and ($post or $get) and none of ($not*)
}

rule php_urlvar_recon_exec: critical {
  meta:
    description = "Runs programs, gets URL data, and looks up system info"
    ref         = "Backdoor.PHP.Llama"

  strings:
    $php       = "<?php"
    $e_popen   = "popen("
    $e_exec    = "exec("
    $f_uname   = "uname("
    $f_phpinfo = "phpinfo("
    $x_GET     = "_GET"
    $x_POST    = "_POST"

    $not_php         = "PHP_VERSION_ID"
    $not_mongosh     = "$ mongosh [options] [db address] [file names (ending in .js or .mongodb)]"
    $not_mongosh_php = { 3C 3F 70 68 70 00 00 00 01 0C 51 61 03 00 00 00 02 00 00 00 3F 3E }
    $not_php_group   = "Copyright (c) The PHP Group"
    $not_workaround  = "/* workaround for chrome bug "

  condition:
    filesize < 64KB and any of ($p*) and any of ($e*) and any of ($f*) and any of ($x*) and none of ($not*)
}

rule php_system_to_perl {
  meta:
    ref         = "kinsing"
    description = "Launches Perl from PHP"

  strings:
    $php         = "<?php"
    $system_perl = /system\([\'\"]perl/

  condition:
    filesize < 64KB and all of them
}

rule php_eval_gzinflate_base64_backdoor: critical {
  meta:
    ref = "xoxo"

  strings:
    $f_eval          = "eval("
    $f_html_special  = "htmlspecialchars_decode"
    $f_gzinflate     = "gzinflate("
    $f_base64_decode = "base64_decode"

    $not_js          = " ?? "
    $not_js2         = " === "
    $not_js3         = "const"
    $not_js4         = "this."
    $not_js5         = "throw"
    $not_mongosh_php = { 3C 3F 70 68 70 00 00 00 01 0C 51 61 03 00 00 00 02 00 00 00 3F 3E }
    $not_php         = "PHP_FLOAT_DIG" fullword
    $not_workaround  = "/* workaround for chrome bug "

  condition:
    filesize < 64KB and all of ($f*) and none of ($not*)
}

rule php_obfuscated_with_hex_characters: high {
  meta:
    description = "PHP obfuscated with multiple hex characters"

  strings:
    $php         = "<?php"
    $hex         = /\\x\w{2}\w\\x/
    $hex_not_mix = /\\x\w{2}\w\\\d/

    $not_char_refs   = "character_references"
    $not_auto        = "AUTOMATICALLY GENERATED"
    $not_mongosh_php = { 3C 3F 70 68 70 00 00 00 01 0C 51 61 03 00 00 00 02 00 00 00 3F 3E }

  condition:
    filesize < 64KB and $php and (#hex > 5 or #hex_not_mix > 5) and none of ($not*)
}

rule php_base64_eval_uname: critical {
  meta:
    description = "PHP code that calls eval, uname, and base64_decode"

  strings:
    $f_php           = "<?php"
    $f_eval          = "eval("
    $f_uname         = "_uname()"
    $f_base64_decode = "base64_decode"

    $not_php_group  = "Copyright (c) The PHP Group"
    $not_workaround = "/* workaround for chrome bug "

  condition:
    filesize < 64KB and all of ($f*) and none of ($not*)
}

rule php_post_system: medium {
  meta:
    description = "Accepts GET/POST variables, executes code"

  strings:
    $php         = "<?php"
    $method_post = "_POST"
    $method_get  = "_GET"
    $system      = "system("

    $not_mongosh     = "$ mongosh [options] [db address] [file names (ending in .js or .mongodb)]"
    $not_mongosh_php = { 3C 3F 70 68 70 00 00 00 01 0C 51 61 03 00 00 00 02 00 00 00 3F 3E }
    $not_php_group   = "Copyright (c) The PHP Group"
    $not_workaround  = "/* workaround for chrome bug "

  condition:
    filesize < 64KB and $php and any of ($method*) and $system and none of ($not*)
}

rule php_error_reporting_disable: high {
  meta:
    description = "sets configuration, turns off error reporting"

  strings:
    $error_reporting = "error_reporting(0)"
    $ini_set         = "ini_set("

  condition:
    all of them
}

rule php_system_manipulation: high {
  meta:
    description = "multiple forms of system manipulation"

  strings:
    $php            = "<?php"
    $chdir          = "chdir("
    $mkdir          = "mkdir("
    $system         = "system("
    $fopen          = "fopen("
    $fwrite         = "fwrite("
    $posix_getpwuid = "posix_getpwuid("
    $symlink        = "symlink("

    $not_workaround = "/* workaround for chrome bug "

  condition:
    filesize < 64KB and $php and 80 % of them and none of ($not*)
}

rule php_system_hex: critical {
  meta:
    description = "runs hex-obfuscated command-lines"

  strings:
    $system_hex = "system(\"\\x"

  condition:
    filesize < 64KB and any of them
}

rule php_insecure_curl_uploader: high {
  meta:
    description = "PHP code that evaluates remote content and disables SSL verification"

  strings:
    $CURLOPT_SSL_VERIFYPEER = "CURLOPT_SSL_VERIFYPEER"
    $php                    = "<?php"
    $f_file_get_contents    = "file_get_contents("
    $f_eval                 = "eval("
    $f_stream_get_contents  = "stream_get_contents("
    $not_php                = "PHP_VERSION_ID"

  condition:
    $CURLOPT_SSL_VERIFYPEER and $php and any of ($f*) and none of ($not*)
}

rule php_eval_get_contents: high {
  meta:
    description = "PHP code that may evaluate remote file contents"

  strings:
    $php                   = "<?php"
    $f_file_get_contents   = "file_get_contents("
    $f_eval                = "eval("
    $f_stream_get_contents = "stream_get_contents("
    $not_reference         = "stream_register_wrapper("

  condition:
    filesize < 65536 and $php and all of ($f*) and none of ($not*)
}

rule php_is_jpeg: critical {
  meta:
    description = "PHP script embedded within JPEG file"

  strings:
    $jfif        = "JFIF"
    $icc_profile = "ICC_PROFILE"
    $php         = "<?php"

  condition:
    filesize < 2MB and all of them
}

rule php_copy_files: high {
  meta:
    description = "copies files uploaded to it"

  strings:
    $copy_files = "@copy($_FILES"

  condition:
    filesize < 64KB and all of them
}

rule php_base64_encoded: critical {
  meta:
    description = "accepts POST/COOKIE input and uses base64"

  strings:
    $php           = "<?php " base64
    $_POST         = "$_POST" base64
    $_COOKIE       = "$_COOKIE" base64
    $base64_decode = "base64_decode" base64
    $base64_encode = "base64_encode" base64

  condition:
    filesize < 64KB and $php and any of ($_*) and any of ($base*)
}

rule php_run_obfuscated: critical {
  meta:
    description = "accepts input and runs obfuscated code"

  strings:
    $f_str_replace      = "str_replace"
    $f_display_errors   = "display_errors"
    $f_output_buffering = "output_buffering"
    $i_get              = "$_GET["
    $i_post             = "$_POST["
    $i_cookie           = "$_COOKIE["
    $o_dynamic_single   = /\$\w {0,2}= \$\w\(/
    $o_single_concat    = /\$\w . \$\w . \$\w ./
    $o_single_set       = /\$\w = \w\(\)\;/
    $o_recursive_single = /\$[a-zA-Z_]\w*\(\$[a-zA-Z_]\w*\(/

  condition:
    filesize < 65535 and 2 of ($f*) and any of ($i*) and 2 of ($o*)
}
