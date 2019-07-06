import "androguard"
import "file"
import "cuckoo"


rule ApkPackerApplication_1
{
	meta:
		description = "ApkPackerApplication samples"

	strings:
		$string_1 = "apkpacker.ApkPackerApplication"
		$string_2 = "realApplication"
		
	condition:
		all of ($string_*)
		
}