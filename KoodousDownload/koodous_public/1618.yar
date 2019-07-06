import "androguard"
import "file"
import "cuckoo"


rule Adload_PUA
{
	meta:
		description = "This rule detects the Adload potential Unwanted"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "aquery/temp"
		$b = "Ljava/security/Permission;"
		$c = "getActiveNetworkInfo"
		$d = "com.appquanta.wk.MainService.DOWNLOAD_PROGRESS"
		$e = "modifyThread"
		$f = "init_url"

	condition:
		all of them		
}