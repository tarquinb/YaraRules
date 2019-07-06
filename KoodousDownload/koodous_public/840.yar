import "androguard"

rule apk_inside
{

	strings:
		$a = /META-INF\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/

	condition:
		$a
		
}