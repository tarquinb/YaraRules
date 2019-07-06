import "androguard"

rule Android_pinkLocker
{
	meta:
		description = "Yara detection for Android Locker app named Pink Club"
		sample = "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"
		author = "https://twitter.com/5h1vang"
		
	strings:
		$str_1 = "arnrsiec sisani"
		$str_2 = "rhguecisoijng ts"
		$str_3 = "assets/data.db"
		$str_4 = "res/xml/device_admin_sample.xmlPK" 

	condition:
		androguard.url(/lineout\.pw/) or 
		androguard.certificate.sha1("D88B53449F6CAC93E65CA5E224A5EAD3E990921E") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		all of ($str_*)
		
}