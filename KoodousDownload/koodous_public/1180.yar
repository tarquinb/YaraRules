import "androguard"

rule Android_HummingBad
{
	meta:
		description = "This rule detects Android.HummingBad"
		sample = "ed14da6b576910aaff07b37f5f5d283de8527a1b "
		source = "http://blog.checkpoint.com/2016/02/04/hummingbad-a-persistent-mobile-chain-attack/"

	strings:
		$string_1 = "assets/right_core.apk"
		$string_2 = "assets/right_core"
		
	
	condition:
		$string_1 or $string_2
		
}