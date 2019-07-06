import "androguard"


rule droidcollector
{
	meta:
		description = "Detect stealer tool (Sending collected data to ext server"

	strings:
		$a = "http://85.10.199.40/ss/media1.php"
		$b = "http://85.10.199.40/ss/xml22.php"
	condition:
		androguard.url(/85\.10\.199\.40/) or $a or $b
}