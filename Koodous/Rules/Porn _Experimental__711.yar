import "androguard"

rule Porn : official
{
	meta:
		description = "Experimental rule about Porn samples"
		sample = "-"

	strings:
		$a = "porn" nocase

	condition:
	
		androguard.package_name(/porn/) and $a 
		or (androguard.package_name(/porn/) and $a and androguard.permission(/android.permission.SEND_SMS/))
			
}