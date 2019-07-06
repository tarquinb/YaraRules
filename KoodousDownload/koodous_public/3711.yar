import "androguard"
import "file"

//Exercise for team 16028,16008,16010,16022 Android malware Samples

rule bankbot_discoverer
{
	meta:
		description = "This rule detects the bankbot app based on md5 and sha1"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
		//source = "https://github.com/fs0c131y/Android-Bankbot,https://vms.drweb.com/virus/?i=8939438&virus_name=Android.BankBot.136.origin&lng=en"

	
	condition:
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") and		
		androguard.url(/37.1.207.31\api\?id=7/) or
		androguard.package_name(/untoenynh/) and
		androguard.permission(/SEND_SMS/) and
		androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/INTERNET/) and
		androguard.permission(/READ_LOGS/) and
		androguard.permission(/WRITE_SMS/) and
		androguard.permission(/ACCESS_NETWORK_STATE/) and
		androguard.permission(/GET_TASKS/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/RECEIVE_SMS/) and
		androguard.permission(/READ_PHONE_STATE/) and
		androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/READ_CONTACTS/) and
		androguard.permission(/READ_SMS/)
}