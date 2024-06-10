rule ShinnyShield
{
meta:
	id = "4kRs05vapnmQ15Bz1V4RDu"
	fingerprint = "efbf32d12e094c838e2375689bbafeadb7859529ba87aefb45ae0a76575faf1d"
	version = "1.0"
	first_imported = "2023-08-01"
	last_modified = "2023-08-01"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Worm that spreads via Call of Duty Modern Warfare 2, 2009 version."
	reference = "https://techcrunch.com/2023/07/27/hackers-are-infecting-call-of-duty-players-with-a-self-spreading-malware" 

strings:
    $msg_dbg1 = "Adding legitimate lobby to party list." ascii wide
    $msg_dbg2 = "Discarded QoS response from modded lobby." ascii wide
    $msg_dbg3 = "Handled join accept from " ascii wide
    $msg_dbg4 = "Handled join request from " ascii wide
    $msg_dbg5 = "Incorrect exe or mw2 version!" ascii wide
    $msg_dbg6 = "Locking the RCE to " ascii wide
    $msg_dbg7 = "Received packet from " ascii wide
    $msg_dbg8 = "Refusing to join blacklisted lobby." ascii wide
    $msg_dbg9 = "Unauthorized RCE attempt detected." ascii wide
    $msg_dbg10 = "Unknown or missing worm instruction." ascii wide
    $msg_dbg11 = "User was randomly selected to be a spreader in modded lobbies." ascii wide
    $msg_dbg12 = "User was selected to be a host/ignore modded lobbies/join unmodded lobbies only" ascii wide
    $msg_worm1 = "Worm deactivated by control server." ascii wide
    $msg_worm2 = "Worm failed to retrieve data from the control server." ascii wide
    $msg_worm3 = "Worm killed by control server." ascii wide
    $msg_worm4 = "Worm up to date." ascii wide
    $msg_worm5 = "wormStatus infected %s" ascii wide
    $msg_worm6 = "get cucked by shiny" ascii wide

    $pdb = "F:\\1337 Call Of Duty\\dxproxies\\DirectX-Wrappers\\Release\\dsound.pdb" ascii wide

    $exp = "joinParty 149 1 1 0 0 0 32 0 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17"
    
condition:
    3 of ($msg_*) or $pdb or $exp
}
