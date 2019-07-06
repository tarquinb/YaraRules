import "androguard"


//Exercise for team 16028,16008,16010,16022 Android malware Samples

rule bankbot_discoverer
{
	meta:
		description = "This rule detects the bankbot app based on various info"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
		family = "bankbot"

strings:
		$s1 = "overlayMode"
		$s2 = "disable_forward_calls"
		$s3 = "suggest_text_2_url"
		$s4 = "popupWindow"
		$s5 = "rootId"
	
	condition:
		androguard.package_name("com.tvone.untoenynh") and
		androguard.permission(/android.permission.READ_CONTACTS/) or
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.permission(/android.permission.RECEIVE_SMS/) or
		androguard.permission(/android.permission.READ_SMS/) or
		androguard.permission(/android.permission.READ_LOGS/) or
		androguard.permission(/android.permission.READ_PHONE_STATE/) or
		androguard.permission(/android.permission.MODIFY_PHONE_STATE/) or
		androguard.permission(/android.permission.QUICKBOOT_POWERON/) or
		androguard.permission(/android.permission.WRITE_SMS/) or
		androguard.permission(/android.permission.GET_TASKS/) or
		androguard.permission(/android.permission.WAKE_LOCK/) or
		androguard.permission(/android.permission.CALL_PHONE/) or
		androguard.permission(/android.permission.MODIFY_AUDIO_SETTINGS/) or
		androguard.permission(/android.permission.INTERNET/) or
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") or
		androguard.url(/37.1.207.31\api\?id=7/) or
		any of ($s*)		
		}