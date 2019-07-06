import "androguard"


rule slempo_service_fb
{
	meta:
		description = "Slempo service malware"
		

	condition:
		androguard.package_name("/slempo.service/") and
		androguard.activity("/slempo.service.activities.FB/")
		
		
}