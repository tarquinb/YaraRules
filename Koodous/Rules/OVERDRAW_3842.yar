import "androguard"


rule koodous : official
{
	meta:
		description = "This rule detects the overdraw applications"

	condition:
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
		
}