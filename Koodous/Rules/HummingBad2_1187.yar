import "androguard"
import "file"

rule HummingBad : urls
{
	meta:
		description = "This rule detects APKs in HummingBad Malware Chain"
		sample = "72901c0214deb86527c178dcd4ecf73d74cac14eaaaffc49eeb00c7fb3343e79"

	strings:
		$string_1 = "assets/daemon.bmp"
		$string_2 = "assets/module_encrypt.jar"
		$string_3 = "assets/daemon"

	condition:
		($string_1 or $string_3) and $string_2
		
}