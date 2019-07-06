import "androguard"
import "file"
import "cuckoo"


rule DroidJack
{
	meta:
		description = "Detects only the ones that weren't obfuscated. Such as the samples like the repackaged Pokemon Go APK"
		family = "DroidJack"
		
	strings:
		$a = "droidjack"
		$b = "incoming_number"
		
	condition:
		($a and $b)
		
}