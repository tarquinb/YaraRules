rule shuanet:dropper
{
	meta:
		description = "This rule detects shuanet apps"
		sample = "ee8eb1c47aac2d00aa16dd8eecbae7a7bf415b3a44bc0c299ad0b58bc8e78260"

	strings:
		$a = "/system/app/System_Framework.apk"
		$b = "/system/app/System_Ad.apk"

	condition:
		all of them
		
}