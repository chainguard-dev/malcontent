
rule base64_php_functions : medium {
  meta:
    description = "References PHP functions in base64 form"
    hash_2023_0xShell_0xObs = "6391e05c8afc30de1e7980dda872547620754ce55c36da15d4aefae2648a36e5"
    hash_2023_0xShell_0xShellObs = "64771788a20856c7b2a29067f41be9cb7138c11a2cf2a8d17ab4afe73516f1ed"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
  strings:
	$php = "<?php"
	$base64_decode = "base64_decode"

    $f_Array = "Array" base64
    $f_array_push = "array_push" base64
    $f_count = "count" base64
    $f_empty = "empty" base64
    $f_explode = "explode" base64
    $f_foreach = "foreach" base64
    $f_getallheaders = "getallheaders" base64
    $f_gettype = "gettype" base64
    $f_inarray = "in_array" base64
    $f_is_dir = "is_dir" base64
    $f_is_writable = "is_writable" base64
    $f_isset = "isset" base64
    $f_move_uploaded_file = "move_uploaded_file" base64
    $f_scandir = "scandir" base64
    $f_str_pad = "str_pad" base64
    $f_strlen = "strlen" base64
    $f_strpos = "strpos" base64
    $f_assert = "assert" base64
    $f_create_function = "create_function" base64
    $f_curl_exec = "curl_exec" base64
    $f_curl_setopt = "curl_setopt" base64
    $f_current_user = "wp_get_current_user" base64
    $f_exec = "exec" base64
    $f_fclose = "fclose" base64
    $f_fgets = "fgets" base64
    $f_file_get_contents = "file_get_contents" base64
    $f_file_put_contents = "file_put_contents" base64
    $f_fopen = "fopen" base64
    $f_fputs = "fputs" base64
    $f_fread = "fread" base64
    $f_fsockopen = "fsockopen" base64
    $f_ftruncate = "ftruncate" base64
    $f_fwrite = "fwrite" base64
    $f_ini_set = "ini_set" base64
    $f_ob_start = "ob_start" base64
    $f_passthru = "passthru" base64
    $f_preg_replace = "preg_replace" base64
    $f_proc_open = "proc_open" base64
    $f_rawurldecode = "rawurldecode" base64
    $f_session_start = "session_start" base64
    $f_set_time_limit = "set_time_limit" base64
    $f_shell_exec = "shell_exec" base64
    $f_system = "system" base64
    $f_unlink = "unlink" base64
    $f_unserialize = "unserialize" base64
    $f_update_option = "update_option" base64
    $f_upload_dir = "wp_upload_dir" base64
    $f_wp_nonce_field = "wp_nonce_field" base64
    $f_wp_verify_nonce = "wp_verify_nonce" base64
  condition:
    $php and $base64_decode and any of them
}

rule base64_php_functions_multiple : critical {
  meta:
    description = "References multiple PHP functions in base64 form"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_0xencbase = "50057362c139184abb74a6c4ec10700477dcefc8530cf356607737539845ca54"
    hash_2023_0xShell_wesobase = "17a1219bf38d953ed22bbddd5aaf1811b9380ad0535089e6721d755a00bddbd0"
  strings:
	$php = "<?php"
	$base64_decode = "base64_decode"

    $f_Array = "Array" base64
    $f_array_push = "array_push" base64
    $f_count = "count" base64
    $f_empty = "empty" base64
    $f_explode = "explode" base64
    $f_foreach = "foreach" base64
    $f_getallheaders = "getallheaders" base64
    $f_gettype = "gettype" base64
    $f_inarray = "in_array" base64
    $f_is_dir = "is_dir" base64
    $f_is_writable = "is_writable" base64
    $f_isset = "isset" base64
    $f_move_uploaded_file = "move_uploaded_file" base64
    $f_scandir = "scandir" base64
    $f_str_pad = "str_pad" base64
    $f_strlen = "strlen" base64
    $f_strpos = "strpos" base64
    $f_assert = "assert" base64
    $f_create_function = "create_function" base64
    $f_curl_exec = "curl_exec" base64
    $f_curl_setopt = "curl_setopt" base64
    $f_current_user = "wp_get_current_user" base64
    $f_exec = "exec" base64
    $f_fclose = "fclose" base64
    $f_fgets = "fgets" base64
    $f_file_get_contents = "file_get_contents" base64
    $f_file_put_contents = "file_put_contents" base64
    $f_fopen = "fopen" base64
    $f_fputs = "fputs" base64
    $f_fread = "fread" base64
    $f_fsockopen = "fsockopen" base64
    $f_ftruncate = "ftruncate" base64
    $f_fwrite = "fwrite" base64
    $f_ini_set = "ini_set" base64
    $f_ob_start = "ob_start" base64
    $f_passthru = "passthru" base64
    $f_preg_replace = "preg_replace" base64
    $f_proc_open = "proc_open" base64
    $f_rawurldecode = "rawurldecode" base64
    $f_session_start = "session_start" base64
    $f_set_time_limit = "set_time_limit" base64
    $f_shell_exec = "shell_exec" base64
    $f_system = "system" base64
    $f_unlink = "unlink" base64
    $f_unserialize = "unserialize" base64
    $f_update_option = "update_option" base64
    $f_upload_dir = "wp_upload_dir" base64
    $f_wp_nonce_field = "wp_nonce_field" base64
    $f_wp_verify_nonce = "wp_verify_nonce" base64
  condition:
    $php and $base64_decode and 2 of ($f_*)
}
