import "androguard"


rule Clevernet : Adware
{
	condition:
		androguard.url(/clevernet/)
		
}