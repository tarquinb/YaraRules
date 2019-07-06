import "androguard"

rule MazarBot
{
	meta:
		description = "This rule detects Android.MazarBot"
		sample = "16bce98604e9af106a70505fb0065babbfc27b992db0c231e691cb1c9ae6377b "
		source = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"

	strings:
		$string_1 = "assets/armeabi/polipo.mp3"
		$string_2 = "assets/armeabi/polipo_old.mp3"
		$string_3 = "assets/armeabi/tor.mp3"
		$string_4 = "assets/armeabi/tor_old.mp3"
		$string_5 = "assets/polipo.mp3"
		$string_6 = "assets/polipo_old.mp3"
		$string_7 = "assets/tor.mp3"
		$string_8 = "assets/tor_old.mp3"
		$string_9 = "assets/x86/polipo.mp3"
		$string_10 = "assets/x86/polipo_old.mp3"
		$string_11 = "assets/x86/tor.mp3"
		$string_12 = "assets/x86/tor_old.mp3"

	
	condition:
		(($string_1 or $string_2) and ($string_3 or $string_4)) or 
		(($string_9 or $string_10) and ($string_11 or $string_12)) or
		(($string_5 or $string_6) and ($string_7 or $string_8)) 

		
}