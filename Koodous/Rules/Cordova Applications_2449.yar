import "androguard"

rule cordova
{
	meta:
		description = "This rule detects Cordova Apps"

	strings:
		$a = "org.apache.cordova"
		$b = "com.adobe.phonegap"

	condition:
		$a or $b
		
		
}