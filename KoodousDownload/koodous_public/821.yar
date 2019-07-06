rule apk_inside
{
	meta:
		description = "This rule detects an APK file inside META-INF folder, which is not checked by Android system during installation"
		inspiration = "http://blog.trustlook.com/2015/09/09/android-signature-verification-vulnerability-and-exploitation/"

	strings:
		$a = /META-INF\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/

	condition:
		$a
		
}