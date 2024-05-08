
rule php_possible_backdoor : critical {
  strings:
    $php = "<?php"
    $php_or = "<? "
    $f_base64_decode = "base64_decode"
    $f_strrev = "strrev"
    $f_rot13 = "str_rot13"
    $f_explode = "explode"
    $f_preg = "preg_replace"
    $f_serialize = "serialize"
    $f_gzinflate = "gzinflate"
    $f_remote_addr = "REMOTE_ADDR"
    $f_exec = "exec("
    $eval = "eval"
    $not_aprutil = "APR-UTIL"
    $not_syntax = "syntax file"
    $not_reference = "stream_register_wrapper"
  condition:
    filesize < 1048576 and $eval and 1 of ($php*) and 4 of ($f_*) and none of ($not*)
}

rule php_eval_base64_decode : critical {
  strings:
    $eval_base64_decode = "eval(base64_decode"
  condition:
    any of them
}

rule php_executor : critical {
  strings:
    $php = "<?php"
    $f_shell_exec = "shell_exec("
    $f_user = "get_current_user("
  condition:
    filesize < 1048576 and $php and all of ($f_*)
}

rule php_bin_hashbang : critical {
  meta:
    hash_2023_UPX_0a07c056fec72668d3f05863f103987cc1aaec92e72148bf16db6cfd58308617_elf_x86_64 = "94f4de1bd8c85b8f820bab936ec16cdb7f7bc19fa60d46ea8106cada4acc79a2"
  strings:
    $php = "<?php"
    $script = "#!/bin/"
    $post = "$_POST" fullword
    $get = "$_GET" fullword
    $not_php = "PHP_VERSION_ID"
  condition:
    $php and $script and ($post or $get) and none of ($not*)
}

rule php_urlvar_recon_exec : critical {
  meta:
    description = "Runs programs, gets URL data, and looks up system info"
    ref = "Backdoor.PHP.Llama"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
  strings:
    $php = "<?php"
    $e_popen = "popen("
    $e_exec = "exec("
    $f_uname = "uname("
    $f_phpinfo = "phpinfo("
    $x_GET = "_GET"
    $x_POST = "_POST"
    $not_php = "PHP_VERSION_ID"
  condition:
    any of ($p*) and any of ($e*) and any of ($f*) and any of ($x*) and none of ($not*)
}

rule php_system_to_perl {
  meta:
    ref = "kinsing"
  strings:
    $php = "<?php"
    $system_perl = /system\([\'\"]perl/
  condition:
    all of them
}

rule php_eval_gzinflate_base64_backdoor : critical {
  meta:
    ref = "xoxo"
  strings:
    $f_eval = "eval("
    $f_html_special = "htmlspecialchars_decode"
    $f_gzinflate = "gzinflate("
    $f_base64_decode = "base64_decode"
    $not_php = "PHP_FLOAT_DIG" fullword
  condition:
    all of ($f*) and none of ($not*)
}

rule php_obfuscated_with_hex_characters : critical {
  strings:
    $php = "<?php"
    $hex = /\\x\w{2}\w\\x/
    $hex_not_mix = /\\x\w{2}\w\\\d/
  condition:
    $php and (#hex > 5 or #hex_not_mix > 5)
}

rule php_base64_eval_uname : critical {
  strings:
    $eval = "eval("
    $html_special = "uname()"
    $base64_decode = "base64_decode"
  condition:
    all of them
}

rule php_post_system : suspicious {
  meta:
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_UPX_0a07c056fec72668d3f05863f103987cc1aaec92e72148bf16db6cfd58308617_elf_x86_64 = "94f4de1bd8c85b8f820bab936ec16cdb7f7bc19fa60d46ea8106cada4acc79a2"
  strings:
    $php = "<?php"
    $method_post = "_POST"
    $method_get = "_GET"
    $system = "system("
  condition:
    $php and any of ($method*) and $system
}

rule php_error_reporting_disable : suspicious {
  meta:
    hash_2023_systembc_password = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
  strings:
    $error_reporting = "error_reporting(0)"
    $ini_set = "ini_set("
  condition:
    all of them
}

rule php_system_manipulation : suspicious {
  strings:
    $php = "<?php"
    $chdir = "chdir("
    $mkdir = "mkdir("
    $system = "system("
    $fopen = "fopen("
    $fwrite = "fwrite("
    $posix_getpwuid = "posix_getpwuid("
    $symlink = "symlink("
  condition:
    $php and 80% of them
}

rule php_system_hex : critical {
  strings:
    $system_hex = "system(\"\\x"
  condition:
    any of them
}

rule php_insecure_curl_uploader : critical {
  strings:
    $CURLOPT_SSL_VERIFYPEER = "CURLOPT_SSL_VERIFYPEER"
    $php = "<?php"
    $f_file_get_contents = "file_get_contents"
    $f_eval = "eval"
    $f_stream_get_contents = "stream_get_contents"
    $not_php = "PHP_VERSION_ID"
  condition:
    $CURLOPT_SSL_VERIFYPEER and $php and any of ($f*) and none of ($not*)
}

rule php_eval_get_contents : critical {
  strings:
    $f_file_get_contents = "file_get_contents"
    $f_eval = "eval"
    $f_stream_get_contents = "stream_get_contents"
    $not_reference = "stream_register_wrapper"
  condition:
    all of ($f*) and none of ($not*)
}

rule php_is_jpeg : critical {
  strings:
    $jfif = "JFIF"
    $icc_profile = "ICC_PROFILE"
    $php = "<?php"
  condition:
    all of them
}

rule php_copy_files : suspicious {
  strings:
    $copy_files = "@copy($_FILES"
  condition:
    all of them
}

rule php_base64_encoded : critical {
  meta:
    hash_2023_pan_chan_6896 = "6896b02503c15ffa68e17404f1c97fd53ea7b53c336a7b8b34e7767f156a9cf2"
    hash_2023_pan_chan_73ed = "73ed0b692fda696efd5f8e33dc05210e54b17e4e4a39183c8462bcc5a3ba06cc"
    hash_2023_pan_chan_99ed = "99ed2445553e490c912ee8493073cc4340e7c6310b0b7fc425ffe8340c551473"
  strings:
    $php = "<?php " base64
    $_POST = "$_POST" base64
    $_COOKIE = "$_COOKIE" base64
    $base64_decode = "base64_decode" base64
    $base64_encode = "base64_decode" base64
  condition:
    any of them
}
