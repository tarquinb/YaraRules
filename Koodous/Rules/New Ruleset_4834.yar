import "androguard"


rule bzwbk
{
	meta:
		description = "1st test yara rule for detect all bzwbk banking app"
		
	

	condition:
		
		androguard.app_name(/bzwbk/) or
		androguard.app_name(/bzwbk24/)or
		androguard.app_name(/BZWBK24/) or
		androguard.app_name(/BZWBK/)or 
		
		androguard.app_name(/bzwbk mobile/) or
		androguard.app_name(/bzwbk24 mobile/)or
		androguard.app_name(/BZWBK24 mobile/) or
		androguard.app_name(/BZWBK mobile/)or
		androguard.app_name("bzwbk*")or
		androguard.app_name(/bzwbk*/)
		
		
}