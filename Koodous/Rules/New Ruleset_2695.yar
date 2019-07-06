import "androguard"

rule simplerule
{
	meta:
		description = "This rule detects a SMS Fraud malware"

	condition:
		androguard.package_name("com.hsgame.")
		
}