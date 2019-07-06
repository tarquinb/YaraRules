import "androguard"



rule taskhijack3 : official
{
	meta:
		date = "2018-02-09"
		description = "Task Hijack #HST3 spoofing"
		reference = "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
		reference1 = "Power by dmanzanero"
		
	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"
		
	condition:
		$file and ($a or $b)
		
}