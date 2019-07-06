import "androguard"

rule adware: installer
{

	condition:
		androguard.package_name("installer.com.bithack.apparatus")
		
		
}