import "androguard"

rule LockeScreen
{
	meta:
		description = "https://twitter.com/LukasStefanko/status/687533750838792192"
		sample = "905556a563cfefbc85b4b82532d5e7bb2e01effa25cf8eb23fdbd47d2973ab5b 84cc270c6b6e07e96b34072aff42cd4e01424720abd7c9dfc61e96eb73508112"

	strings:
		$string_a = "lockNow"
		$string_b = "logcat -v threadtime"
		$string_c = "LLogCatBroadcaster"
		$string_d = "force-lock"
		

	condition:
		
		all of ($string_*) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) 

		
}