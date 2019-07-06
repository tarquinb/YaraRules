import "androguard"



rule HummingBad : malware
{
	meta:
		description = "https://www.checkpoint.com/downloads/resources/wp-hummingbad-research-report.pdf"


	strings:
		$a = "com.android.vending.INSTALL_REFERRER"
		$b = "Superuser.apk"

	condition:
		(androguard.package_name("Com.andr0id.cmvchinme") or
		androguard.package_name("Com.swiping.whale") or
		androguard.package_name("Com.andr0id.cmvchinmf") or
		androguard.package_name("com.quick.launcher")) and
		
		$a and $b
		
		
	
}