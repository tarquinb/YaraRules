import "androguard"



rule taskhijack : official
{
	meta:
		date = "2015-09-21"
		description = "Posible task Hijack"
		reference = "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
		
	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"
		
	condition:
		$file and ($a or $b)
		
}