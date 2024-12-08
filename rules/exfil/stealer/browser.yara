rule cookies: medium {
  meta:
    description = "may access cookies"

  strings:
    $Cookies = "Cookies"
    $cookies = "cookies"

  condition:
    filesize < 128KB and any of them
}

rule multiple_browser_credentials: high {
  meta:
    description = "accesses credentials from multiple browsers"

  strings:
    $c_library_keychains     = "/Library/Keychains"
    $c_cookies_sqlite        = "cookies.sqlite"
    $c_moz_cookies           = "moz_cookies"
    $c_opera_gx              = "OperaGX"
    $c_keychain_db           = "login.keychain-db"
    $c_dscl_local            = "dscl /Local/Default"
    $c_osascript             = "osascript"
    $c_find_generic_password = "find-generic-password"
    $not_security            = "PROGRAM:security"
    $not_verbose             = "system_verbose"
    $not_kandji              = "com.kandji.profile.mdmprofile"
    $not_xul                 = "XUL_APP_FILE"

  condition:
    3 of ($c_*) and none of ($not_*)
}

rule multiple_browser_refs: high {
  meta:
    description = "Makes references to multiple browser credentials"

  strings:
    $fs_config             = ".config" fullword
    $fs_app_support        = "Application Support"
    $fs_app_support_slash  = "Application\\ Support"
    $fs_chrome             = "Google/Chrome"
    $fs_chrome_local_state = "Chrome/Local State"
    $fs_chrome_userdata    = "Chrome/User Data"
    $fs_cookies            = "Cookies"
    $fs_cookies_sqlite     = "cookies.sqlite"
    $fs_firefox            = "Mozilla/Firefox"
    $fs_firefox_profiles   = "Firefox/Profiles"
    $fs_form_history       = "formhistory.sqlite"
    $fs_moz_cookies        = "moz_cookies"
    $fs_places_sqlite      = "places.sqlite"
    $fs_roaming            = "Roaming/"
    $fs_user_data          = "User Data"
    $name_brave            = "Brave-Browser"
    $name_brave_software   = "BraveSoftw"
    $name_chrome           = "Google Chrome"
    $name_opera_gx         = "Opera" fullword
    $name_firefox          = "Firefox"
    $name_opera            = "Opera Software"
    $name_yandex           = "YandexBrowser"

    $not_chromium               = "ChromiumBrowser"
    $not_chromium_comment       = "When this is enabled, Chromium can use"
    $not_chromium_issues        = "https://issues.chromium.org/"
    $not_google                 = "developed by Google"
    $not_google_chrome_software = "The Google Chrome software"
    $not_bugzilla               = "https://bugzilla.mozilla.org"
    $not_ff_js                  = "Firefox can even throw an error"
    $not_generated_comment      = "// This file is generated"
    $not_generated_file         = "/utils/generate_types/index.js"

  condition:
    filesize < 20MB and 3 of ($name*) and 3 of ($fs*) and none of ($not*)
}

rule userdata_browser_archiver: medium {
  meta:
    description = "Uses HTTP, archives, and references multiple browsers"

  strings:
    $d_config      = ".config" fullword
    $d_app_support = "Application Support" fullword
    $d_state       = "User Data" fullword
    $h_http        = "http" fullword
    $h_https       = "https" fullword
    $h_POST        = "POST" fullword
    $h_discord     = "Discord" fullword
    $z_zip         = "zip" fullword
    $z_ZIP         = "ZIP" fullword
    $z_ditto       = "ditto" fullword
    $z_tar         = "tar" fullword
    $z_store       = "assasans/storage" fullword
    $b_Yandex      = "Yandex"
    $b_Brave       = "Brave"
    $b_Firefox     = "Firefox"
    $b_Safari      = "Safari"
    $b_Chrome      = "Chrome"
    $b_moz         = "Roaming/Moz"
    $b_Opera       = "Opera" fullword

    $not_chromium               = "ChromiumBrowser"
    $not_chromium_comment       = "When this is enabled, Chromium can use"
    $not_chromium_issues        = "https://issues.chromium.org/"
    $not_google                 = "developed by Google"
    $not_google_chrome_software = "The Google Chrome software"
    $not_bugzilla               = "https://bugzilla.mozilla.org"
    $not_ff_js                  = "Firefox can even throw an error"
    $not_generated_comment      = "// This file is generated"
    $not_generated_file         = "/utils/generate_types/index.js"
    $not_no_user_data           = "No User Data"

  condition:
    filesize < 20MB and any of ($d*) and any of ($h*) and any of ($z*) and 4 of ($b*) and none of ($not*)
}

rule smaller_userdata_browser_archiver: high {
  meta:
    description = "Uses HTTP, archives, and references multiple browsers"

  strings:
    $d_config      = ".config" fullword
    $d_app_support = "Application Support" fullword
    $d_state       = "User Data" fullword
    $h_http        = "http" fullword
    $h_https       = "https" fullword
    $h_POST        = "POST" fullword
    $h_discord     = "Discord" fullword
    $z_zip         = "zip" fullword
    $z_ZIP         = "ZIP" fullword
    $z_ditto       = "ditto" fullword
    $z_tar         = "tar" fullword
    $z_store       = "assasans/storage" fullword
    $b_Yandex      = "Yandex"
    $b_Brave       = "Brave"
    $b_Firefox     = "Firefox"
    $b_Safari      = "Safari"
    $b_Chrome      = "Chrome"
    $b_moz         = "Roaming/Moz"
    $b_Opera       = "Opera"

    $not_chromium               = "ChromiumBrowser"
    $not_chromium_comment       = "When this is enabled, Chromium can use"
    $not_chromium_issues        = "https://issues.chromium.org/"
    $not_google                 = "developed by Google"
    $not_google_chrome_software = "The Google Chrome software"
    $not_bugzilla               = "https://bugzilla.mozilla.org"
    $not_ff_js                  = "Firefox can even throw an error"
    $not_generated_comment      = "// This file is generated"
    $not_generated_file         = "/utils/generate_types/index.js"

  condition:
    filesize < 64KB and any of ($d*) and any of ($h*) and any of ($z*) and 3 of ($b*) and none of ($not*)
}

rule chrome_encrypted_cookies: critical {
  meta:
    description = "Reads encrypted values from Chrome cookie store"

  strings:
    $select = /SELECT.{0,64}encrypted_value{0,64}cookies/

  condition:
    $select
}

rule leveldb_exfil: high {
  meta:
    description = "Reads values from browser leveldb files"

  strings:
    $h_urlopen = "urlopen"
    $h_https   = "https://"
    $leveldb   = "leveldb" fullword
    $b_Yandox  = "Yandex"
    $b_Discord = "Discord"
    $b_Chrome  = "Google Chrome"
    $b_Opera   = "Opera"
    $b_Brave   = "Brave"

  condition:
    filesize < 3MB and $leveldb and any of ($h*) and 3 of ($b*)
}

rule select_chrome_obviously: high {
  meta:
    description = "Steals data from the Chrome Browser"

  strings:
    $chrome  = "steal_chrome"
    $cookie  = "cookie"
    $cookie2 = "Cookie"

  condition:
    filesize < 1MB and $chrome and any of ($cook*)
}

rule sqlite3_chrome_cookies: high {
  meta:
    description = "Reads Chrome Browser cookies"

  strings:
    $Chrome       = "Chrome"
    $Google       = "Google"
    $Cookies      = "Cookies"
    $sqlite3_up   = "SQLite3"
    $sqlite3_down = "sqlite3"

  condition:
    filesize < 128KB and all of them
}

rule select_chrome_cookies: high {
  meta:
    description = "Reads Chrome Browser cookies"

  strings:
    $Chrome = "Chrome"
    $select = /SELECT \* FROM .{0,1}cookies/

  condition:
    filesize < 128KB and all of them
}

rule sqlite3_chrome_logins: high {
  meta:
    description = "Reads Chrome Browser logins"

  strings:
    $Chrome       = "Chrome"
    $Google       = "Google"
    $login_data   = "Login Data"
    $sqlite3_up   = "SQLite3"
    $sqlite3_down = "sqlite3"

  condition:
    filesize < 128KB and all of them
}

rule select_chrome_logins: high {
  meta:
    description = "Reads Chrome Browser logins"

  strings:
    $Chrome = "Chrome"
    $select = /SELECT \* FROM .{0,1}logins/

  condition:
    filesize < 128KB and all of them
}

rule cookie_crawler: high {
  meta:
    description = "crawls directories looking for application cookies"

  strings:
    $crawlCookies = "crawlCookies"
    $appdata      = "appData"

  condition:
    filesize < 1MB and all of them
}
