import "androguard"
import "file"
import "cuckoo"


rule whatever
{
	meta:
		description = "This rule detects something"


	condition:
		androguard.app_name(/BZWBK/) or 
		androguard.app_name("BZWBK") or 
		androguard.app_name(/bzwbk/) or
		androguard.app_name("bzwbk") or
		androguard.app_name(/BZWBK24/) or
		androguard.app_name(/bzwbk24/) or
		androguard.app_name(/BZWBK24 mobile/) or
		androguard.app_name("BZWBK24 mobile") or
		androguard.app_name(/Santander/) or
		androguard.app_name("Santander")
	
		
}