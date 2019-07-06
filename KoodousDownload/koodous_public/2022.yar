import "androguard"



rule locker : ransomware
{
	meta:
		description = "This rule detects ransomware apps"
		sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"

	condition:
		androguard.package_name("com.simplelocker")
}