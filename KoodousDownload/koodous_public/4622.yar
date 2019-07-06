import "androguard"
import "file"
import "cuckoo"


rule fortnite_appclone
{
	meta:
		description = "This rule detects new Fortnite malicious apps"
		sample = "2a1da7e17edaefc0468dbf25a0f60390"

	strings:
		$a_1 = "StealthMode"
		$a_2 = "onStartCommand"
		$a_3 = "ShowOnLockScreen"
		$a_4 = "The original WhatsApp"
		
		
	condition:
		all of ($a_*)
		
}