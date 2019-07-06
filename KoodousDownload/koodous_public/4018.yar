import "androguard"

rule Exobot1

{
	meta:
		description = "ExoBot0118"
		family = "ExoBot"
	
	condition:
	
		androguard.url("www.doviz.com")	or
		androguard.url("91.214.70.163:7227") or
		androguard.url("sdfdsf.at") or
		androguard.url("api.androidhive.info/images/nav-menu-header-bg.jpg") or		androguard.url("lh3.googleusercontent.com/eCtE_G34M9ygdkmOpYvCag1vBARCmZwnVS6rS5t4JLzJ6QgQSBquM0nuTsCpLhYbKljoyS-txg") or
		androguard.url("sdfsdfa.biz") or
		androguard.url("schemas.android.com/apk/res/android") or
		androguard.url("sdfdsfs.cc") or
		androguard.url("www.androidhive.info") or
		androguard.url("www.doviz.com") or
		androguard.url("ns.adobe.com/xap/1.0") or
		androguard.url("www.inkscape.org") or 
		androguard.url("185.159.129.25:7227") or
		androguard.url("m.dovizz.net")		
}

rule Exobot2

{
	meta:
		description = "ExoBot0118"
		family = "ExoBot"

	condition:
	
		((androguard.permission("android.READ_EXTERNAL_STORAGE")) or
		(androguard.permission("android.RECEIVE_BOOT_COMPLETED")) or
		(androguard.permission("android.INTERNET")) or
		(androguard.permission("android.INSTALL_PACKAGES")) or 
		(androguard.permission("android.ACCESS_NETWORK_STATE")) or
		(androguard.permission("android.INTERNET")) or
		(androguard.permission("android.WRITE_EXTERNAL_STORAGE"))) and Exobot1	

}