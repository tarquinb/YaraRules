import "androguard"
import "file"
import "cuckoo"


rule ransomware
{
	meta:
		description = "This rule detects ransomware android app"
		sample = "b3a9f2023e205fc8e9ff07a7e1ca746b89a7db94a0782ffd18db4f50558a0dd8"

	strings:
		$a = "You are accused of commiting the crime envisaged"
	condition:
		androguard.package_name("com.android.locker") or
		androguard.package_name("com.example.testlock") or
		androguard.url(/api33\/api\.php/) or 
		$a
		
}