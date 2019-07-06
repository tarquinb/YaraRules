import "androguard"

rule thoughtcrime
{
	meta:
		description = "https://github.com/WhisperSystems/Signal-Android/tree/master/src/org/thoughtcrime/securesms"

	condition:
		androguard.permission(/org\.thoughtcrime\.securesms\.ACCESS_SECRETS/) or
		androguard.activity(/org\.thoughtcrime\.securesms\.*/) 
		
}