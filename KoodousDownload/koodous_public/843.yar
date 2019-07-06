import "androguard"



rule Posible_bypass_Screenlock
{
	meta:
		description = "Bypass_Screenlock"



	condition:
		
		androguard.permission(/android.permission.DISABLE_KEYGUARD/)
		
		
}