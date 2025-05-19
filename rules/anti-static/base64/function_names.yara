rule base64_php_functions: medium {
  meta:
    description = "References PHP functions in base64 form"
    filetypes   = "php"

  strings:
    $php           = "<?php"
    $base64_decode = "base64_decode"

    $f_Array              = "Array" base64
    $f_array_push         = "array_push" base64
    $f_count              = "count" base64
    $f_empty              = "empty" base64
    $f_explode            = "explode" base64
    $f_foreach            = "foreach" base64
    $f_getallheaders      = "getallheaders" base64
    $f_gettype            = "gettype" base64
    $f_inarray            = "in_array" base64
    $f_is_dir             = "is_dir" base64
    $f_is_writable        = "is_writable" base64
    $f_isset              = "isset" base64
    $f_move_uploaded_file = "move_uploaded_file" base64
    $f_scandir            = "scandir" base64
    $f_str_pad            = "str_pad" base64
    $f_strlen             = "strlen" base64
    $f_strpos             = "strpos" base64
    $f_assert             = "assert" base64
    $f_create_function    = "create_function" base64
    $f_curl_exec          = "curl_exec" base64
    $f_curl_setopt        = "curl_setopt" base64
    $f_current_user       = "wp_get_current_user" base64
    $f_exec               = "exec" base64
    $f_fclose             = "fclose" base64
    $f_fgets              = "fgets" base64
    $f_file_get_contents  = "file_get_contents" base64
    $f_file_put_contents  = "file_put_contents" base64
    $f_fopen              = "fopen" base64
    $f_fputs              = "fputs" base64
    $f_fread              = "fread" base64
    $f_fsockopen          = "fsockopen" base64
    $f_ftruncate          = "ftruncate" base64
    $f_fwrite             = "fwrite" base64
    $f_ini_set            = "ini_set" base64
    $f_ob_start           = "ob_start" base64
    $f_passthru           = "passthru" base64
    $f_preg_replace       = "preg_replace" base64
    $f_proc_open          = "proc_open" base64
    $f_rawurldecode       = "rawurldecode" base64
    $f_session_start      = "session_start" base64
    $f_set_time_limit     = "set_time_limit" base64
    $f_shell_exec         = "shell_exec" base64
    $f_system             = "system" base64
    $f_unlink             = "unlink" base64
    $f_unserialize        = "unserialize" base64
    $f_update_option      = "update_option" base64
    $f_upload_dir         = "wp_upload_dir" base64
    $f_wp_nonce_field     = "wp_nonce_field" base64
    $f_wp_verify_nonce    = "wp_verify_nonce" base64

    $not_comment     = "// processing instruction, e.g. <?php ?>"
    $not_mongosh     = "$ mongosh [options] [db address] [file names (ending in .js or .mongodb)]"
    $not_mongosh_php = { 3C 3F 70 68 70 00 00 00 01 0C 51 61 03 00 00 00 02 00 00 00 3F 3E }

  condition:
    filesize < 64KB and $php and $base64_decode and any of ($f_*) and none of ($not*)
}

rule base64_php_functions_multiple: critical {
  meta:
    description = "References multiple PHP functions in base64 form"
    filetypes   = "php"

  strings:
    $php           = "<?php"
    $base64_decode = "base64_decode"

    $f_Array              = "Array" base64
    $f_array_push         = "array_push" base64
    $f_count              = "count" base64
    $f_empty              = "empty" base64
    $f_explode            = "explode" base64
    $f_foreach            = "foreach" base64
    $f_getallheaders      = "getallheaders" base64
    $f_gettype            = "gettype" base64
    $f_inarray            = "in_array" base64
    $f_is_dir             = "is_dir" base64
    $f_is_writable        = "is_writable" base64
    $f_isset              = "isset" base64
    $f_move_uploaded_file = "move_uploaded_file" base64
    $f_scandir            = "scandir" base64
    $f_str_pad            = "str_pad" base64
    $f_strlen             = "strlen" base64
    $f_strpos             = "strpos" base64
    $f_assert             = "assert" base64
    $f_create_function    = "create_function" base64
    $f_curl_exec          = "curl_exec" base64
    $f_curl_setopt        = "curl_setopt" base64
    $f_current_user       = "wp_get_current_user" base64
    $f_exec               = "exec" base64
    $f_fclose             = "fclose" base64
    $f_fgets              = "fgets" base64
    $f_file_get_contents  = "file_get_contents" base64
    $f_file_put_contents  = "file_put_contents" base64
    $f_fopen              = "fopen" base64
    $f_fputs              = "fputs" base64
    $f_fread              = "fread" base64
    $f_fsockopen          = "fsockopen" base64
    $f_ftruncate          = "ftruncate" base64
    $f_fwrite             = "fwrite" base64
    $f_ini_set            = "ini_set" base64
    $f_ob_start           = "ob_start" base64
    $f_passthru           = "passthru" base64
    $f_preg_replace       = "preg_replace" base64
    $f_proc_open          = "proc_open" base64
    $f_rawurldecode       = "rawurldecode" base64
    $f_session_start      = "session_start" base64
    $f_set_time_limit     = "set_time_limit" base64
    $f_shell_exec         = "shell_exec" base64
    $f_system             = "system" base64
    $f_unlink             = "unlink" base64
    $f_unserialize        = "unserialize" base64
    $f_update_option      = "update_option" base64
    $f_upload_dir         = "wp_upload_dir" base64
    $f_wp_nonce_field     = "wp_nonce_field" base64
    $f_wp_verify_nonce    = "wp_verify_nonce" base64

    $not_comment         = "// processing instruction, e.g. <?php ?>"
    $not_mongosh         = "lib-boxednode/mongosh"
    $not_mongosh_license = "For license information please see mongosh.js.LICENSE.txt"

  condition:
    $php and $base64_decode and 2 of ($f_*) and none of ($not*)
}

rule base64_python_functions: critical {
  meta:
    description = "contains base64 Python code"
    filetypes   = "py"

  strings:
    $f_exec          = "exec(" base64
    $f_eval          = "eval(" base64
    $f_import_os     = "import os" base64
    $f_import        = "__import__" base64
    $f_importlib     = "importlib" base64
    $f_import_module = "import_module" base64
    $f_urllib        = "urllib.request" base64
    $f_requests_get  = "requests.get" base64
    $f_urlopen       = "urlopen" base64
    $f_read          = "read()" base64
    $f_decode        = "decode()" base64
    $f_b64decode     = "base64.b64decode" base64
    $f_exc           = "except Exception as" base64
    $f_os_system     = "os.system" base64
    $f_os_startfile  = "os.startfile" base64
    $f_os_popen      = "os.popen" base64
    $f_thread        = "threading.Thread" base64
    $f_os_environ    = "os.environ" base64
    $f_with_open     = "with open(" base64
    $not_js          = " ?? " base64
    $not_js2         = " === " base64
    $not_js3         = "const" base64
    $not_js4         = "this." base64
    $not_js5         = "throw" base64

  condition:
    2 of ($f*) and none of ($not*)
}
