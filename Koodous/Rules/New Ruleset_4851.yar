import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the instagram password stealers"
		sample = "7ec580e72b93eb9c5f858890e979f2fe10210d40adc522f93faa7c46cd0958b0"

	strings:
		$instagram = "https://www.instagram.com/accounts/login"
		$password = "'password'"
		$addJavaScript = "addJavascriptInterface"

	condition:

		$instagram and
		$password and
		$addJavaScript
		
}