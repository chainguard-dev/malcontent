rule Pulsar_RAT
{
meta:
	id = "3t0qvuhxPyAAjAGoxh0hzU"
	fingerprint = "v1_sha256_dd4e87f5677cd6a275cbd3f985b25776a040a3f69079877a709477500b6dc4ad"
	version = "1.0"
	date = "2026-01-22"
	modified = "2026-01-22"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Pulsar RAT, based on Quasar RAT."
	category = "MALWARE"
	malware_type = "RAT"
	reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pulsar_rat"

strings:
	$ = "costura.pulsar" 
	$ = "Pulsar.Common" 
	$ = "Pulsar.Client" 
	$ = "Pulsar Client" ascii wide
	$ = "Pulsar HVNC Progress UI" ascii wide
	$ = "PulsarDesktop" ascii wide
	$ = "PulsarMessagePackSerializer" 

condition:
	2 of them
}
