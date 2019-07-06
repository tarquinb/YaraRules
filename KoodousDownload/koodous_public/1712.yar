import "androguard"



rule spynote_pkg
{
	meta:
		description = "Yara rule for detection of different Spynote based on pkg"
		source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "SERVER_IP" nocase
	condition:
		androguard.package_name("dell.scream.application") and 
		$str_1
}