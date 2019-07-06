import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		
}

	strings:
		$dbhook = "SQLiteDatabaseHook"
		$message_str = "preMakeApplication FAIL"

	condition:
		all of them

		
}