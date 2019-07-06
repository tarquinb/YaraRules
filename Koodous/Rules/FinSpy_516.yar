rule FinSpy
{
	meta:
		description = "FinSpy"
		info = "http://maldr0id.blogspot.com.es/2014/10/whatsapp-with-finspy.html"

	strings:
		$a = "4j#e*F9+Ms%|g1~5.3rH!we"

	condition:
		$a
}