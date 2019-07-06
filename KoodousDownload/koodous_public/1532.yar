rule Godless_malware
{
	meta:
		description = "GODLESS Mobile Malware"

	strings:
		$a = "android.intent.action.SCREEN_OFF"
		$b = "system/app/AndroidDaemonFrame.apk"
		$c = "libgodlikelib.so"
		

	condition:

		$a and $b and $c
		
}