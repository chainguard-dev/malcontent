rule Mythic
{
meta:
	id = "69R6s4O4jrRhzpA0GwJdh0"
	fingerprint = "v1_sha256_fd3f6ed7ae8191d98a0f7f3676795be2ab5656d7eed2fa5b4f452bd8610b9fa5"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Mythic, a collaborative, multi-platform, red teaming framework."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/its-a-feature/Mythic"
	tool = "MYTHIC"

strings:
	$ = "access_time"
	$ = "agent_callback_id"
	$ = "c2_profile"
	$ = "c2_profile_id"
	$ = "enc_key_base64"
	$ = "encrypted_exchange_check"
	$ = "file_browser"
	$ = "get_delegate_tasks"
	$ = "get_tasking"
	$ = "is_file"
	$ = "is_screenshot"
	$ = "post_response"
	$ = "send_webhook"
	$ = "task_id"
	$ = "tasking_size"
	$ = "total_chunks"
	$ = "webhook_alert"
	
condition:
	8 of them
}

rule Mythic_Apollo
{
meta:
	id = "5agM09gxQMDgPQacwgnLSf"
	fingerprint = "v1_sha256_73dac1002022c73249469d22cc5d9340e82a5b47c7f913d0e309674751031f08"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Mythic's Apollo agent, a collaborative, multi-platform, red teaming framework."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/its-a-feature/Mythic"
	tool = "MYTHIC"

strings:
	$ = "apollo_tracker_uuid" 
	$ = "mythic_uuid" 
	$ = "MythicMessageEventArgs" 
	$ = "IMythicMessage" 
	$ = "ApolloLogonInformation" 
	$ = "ApolloTokenInformation" 
	$ = "MythicEncryption" 
	$ = "MythicTask" 
	$ = "MythicTaskResponse"
	$ = "MythicTaskStatus" 
	
condition:
	2 of them
}

rule Mythic_Apollo_Tasks
{
meta:
	id = "3Knpy0fO9mMnMIWqjX7Zzn"
	fingerprint = "v1_sha256_a8b6a3da21ae7fb70f5feee93fc9838171fcb3e370458dd1331672d0815f0710"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Mythic's Apollo agent, a collaborative, multi-platform, red teaming framework."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/its-a-feature/Mythic"
	tool = "MYTHIC"

strings:
	$ = "assembly_inject" 
	$ = "blockdlls" 
	$ = "execute_assembly" 
	$ = "execute_coff" 
	$ = "execute_pe" 
	$ = "getprivs" 
	$ = "getsystem" 
	$ = "get_injection_techniques" 
	$ = "inline_assembly" 
	$ = "jobkill" 
	$ = "keylog_inject" 
	$ = "listpipes" 
	$ = "make_token" 
	$ = "net_dclist" 
	$ = "net_localgroup" 
	$ = "net_localgroup_member" 
	$ = "net_shares" 
	$ = "powerpick" 
	$ = "psinject" 
	$ = "register_file" 
	$ = "reg_query" 
	$ = "reg_write_value" 
	$ = "rev2self" 
	$ = "screenshot_inject" 
	$ = "self_delete" 
	$ = "set_injection_technique" 
	$ = "shinject" 
	$ = "spawnto_x64" 
	$ = "spawnto_x86" 
	$ = "steal_token" 
	$ = "wmiexecute"
	
condition:
	20 of them
}

rule Mythic_Apollo_Net
{
meta:
	id = "18TC3KGJ9FKOFcryiefeQ0"
	fingerprint = "v1_sha256_5d24c0ad268da5fcb949f8eb15cefe48196aad0f00c81ca3622c0d88c7ec5e31"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Mythic's Apollo agent, a collaborative, multi-platform, red teaming framework."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/MythicAgents/Apollo"
	tool = "MYTHIC"

strings:
	$ = "get_C2ProfileManager"
	$ = "get_TaskManager"
	$ = "get_FileManager"
	$ = "get_SocksManager"
	$ = "get_PeerManager"
	$ = "get_ProcessManager"
	$ = "get_InjectionManager"
	$ = "get_TicketManager"
	$ = "get_IdentityManager"
	$ = "get_SleepInterval"
	$ = "get_Jitter"
	
condition:
	9 of them
}

