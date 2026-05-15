rule scap_security_guide_content: override {
  meta:
    description                 = "SCAP Security Guide compliance content XML files"
    password_finder_mimipenguin = "low"
    password_prompt_high        = "low"
    rename_system_binary        = "low"
    kmem                        = "low"
    multiple_sys_commands       = "low"
    linux_multi_persist         = "low"
    ssh_backdoor                = "low"
    bash_history_high           = "low"
    linux_server_stealer        = "low"

  strings:
    $scap_sg = "from SCAP Security Guide"
    $ssg_id  = ":ssg-"

  condition:
    filesize < 30MB and all of them
}
