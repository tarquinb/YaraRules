import "androguard"


rule ZooParkv1
{
	meta:
		description = "This rule detects ZooPark malware version 1"
		sample = ""

	condition:
		androguard.url(/rhubarb2\.com/)
		
}



rule ZooParkv2
{
	meta:
		description = "This rule detects ZooPark malware version 2"
		sample = "041b4d2280cae9720a62350de4541172933909380bb02701a7d20f87e670bac4"

	condition:
		androguard.url(/rhubarb3\.com/)
		
}