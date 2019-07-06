import "androguard"

rule POB_1
{
	meta:
		description = "Detects few MyPleasure app"
		
	condition:
		(androguard.service(/ch.nth.android.contentabo.service.DownloadAppService/))
		
}