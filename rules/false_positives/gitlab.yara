import "hash"

rule exec_regex: override {
  meta:
    description                         = "csv_builder_spec.rb"
    SEKOIA_Technique_Csv_Dde_Exec_Regex = "low"

  strings:
    $example1 = "shared_examples 'excel sanitization' do"
    $example2 = "'sanitizes dangerous characters at the beginning of a column'"
    $example3 = "'does not sanitize safe symbols at the beginning of a column'"
    $example4 = "'when dangerous characters are after a line break'"
    $example5 = "'does not append single quote to description'"

  condition:
    filesize < 8192 and all of them
}

rule fetch_command: override {
  meta:
    description            = "install.sh"
    filetypes              = "sh"
    download_and_execute   = "medium"
    high_fetch_command_val = "low"
    possible_dropper       = "harmless"

  condition:
    filesize < 1024 and (hash.sha256(0, filesize) == "316d9c447de581287bf6912947999327360677eae7c51cd62b708f664198f032")
}

rule vscode_extension: override {
  meta:
    description                  = "browser.js"
    leveldb_exfil                = "harmless"
    slack_leveldb                = "harmless"
    unsigned_bitwise_math_excess = "medium"

  strings:
    $secretEntry     = /\{description\:\".*\",id\:\".*\",regex\:.*,(secretGroup\:\d{1},){0,1}keywords\:\[.*\]\}/
    $secretRedactor1 = "_ge=(0,gge.createInterfaceId)(\"SecretRedactor\")"
    $secretRedactor2 = "this.#t=Vt(t,\"[SecretRedactor]\")"

  condition:
    filesize < 3MB and #secretEntry > 0 and all of ($secretRedactor*)
}
