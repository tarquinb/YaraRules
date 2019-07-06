import "androguard"

rule spynote4
{
	meta:
		description = "Yara rule for detection of  Spynote4.0"
		author = "invoker"

	strings:
		$str_1 = "scream" 
		
	condition:
		androguard.package_name("system.operating.dominance.proj") and 
		all of ($str_*)
}