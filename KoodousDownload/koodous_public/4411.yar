import "androguard"
import "file"
import "cuckoo"


rule roaming_mantis_2
{
	meta:
		description = "This rule detects Roaming Mantis samples - https://securitynews.sonicwall.com/xmlpost/roaming-mantis-attacks-android-devices-in-asia-likely-behind-otp-codes-may-8-2018/"
		sample = "2a1da7e17edaefc0468dbf25a0f60390"

	strings:
		$a_1 = "MyWebActivity"
		$a_2 = "gsActivity"
		$a_3 = "MyReceiver"
		$a_4 = "AdminReceiver"
		$a_5 = "CancelNoticeService"
		$a_6 = "MainService"
		
	condition:
		all of ($a_*)
		
}