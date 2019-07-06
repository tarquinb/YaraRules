import "androguard"
import "file"

rule BankingPhisher : string
{
	meta:
		description = "This rule detects APKs in BankingPhisher Malware"
		sample = "8f53d3abc301b4fbb7c83865ffda2f1152d5e347"

	strings:
		$string_1 = "installed.xml"
		$string_2 = "testgate.php"
		
	condition:
		$string_1 or $string_2
}