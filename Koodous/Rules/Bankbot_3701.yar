import "androguard"
import "file"

rule bankbot_discoverer
{
	meta:
		description = "Rule tp detect Bankbot malware"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
		//source = "https://github.com/fs0c131y/Android-Bankbot,https://vms.drweb.com/virus/?i=8939438&virus_name=Android.BankBot.136.origin&lng=en"

	
	condition:
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") or 
		(androguard.url(/37.1.207.31\api\?id=7/) and 
		androguard.package_name(/untoenynh/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/READ_SMS/)
		)

		}