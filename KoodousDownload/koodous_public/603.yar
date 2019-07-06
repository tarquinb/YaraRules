import "androguard"


rule koodous : official
{
	meta:
		description = "Rubobi"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "surprise"
		$b = "r/6UyV_i"

	condition:

		$a and $b and androguard.permission(/android.permission.SEND_SMS/)

		
}