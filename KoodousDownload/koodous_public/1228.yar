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
		$string_5 = "assets/polipo.mp3"
		$string_6 = "assets/polipo_old.mp3"
		$string_9 = "assets/x86/polipo.mp3"
		$string_10 = "assets/x86/polipo_old.mp3"


	
	condition:
		$string_1 or $string_2  or $string_9 or $string_10  or $string_5 or $string_6

		
}