
rule fernet_walker : high {
  meta:
    description = "walks filesystem, encrypts content using Fernet"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    hash_2024_2024_d3duct1v_s2 = "8c914dfa5cb7fd25d87ee802a48e8e63c090ceb400f0fd3cd0bf605bba36a4bd"
  strings:
    $walk = /\w{0,2}\.walk[\(\w\)]{1,16}/
    $fernet = /Fernet[\(\w\)]{1,16}/
    $encrypt = /\w{1,16}.encrypt/
  condition:
    filesize < 65535 and all of them
}

rule fernet_locker : critical {
  meta:
    description = "walks filesystem, encrypts and deletes content using Fernet"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    hash_2024_2024_d3duct1v_s2 = "8c914dfa5cb7fd25d87ee802a48e8e63c090ceb400f0fd3cd0bf605bba36a4bd"
  strings:
    $walk = /\w{0,2}\.walk[\(\w\)]{1,16}/
    $fernet = /Fernet[\(\w\)]{1,16}/
    $encrypt = /\w{1,16}.encrypt/
    $seek = "seek(0)"
    $write = "write("
    $truncate = "truncate("
  condition:
    filesize < 65535 and all of them
}
