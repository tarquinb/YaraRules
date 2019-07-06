rule non_named
{
	meta:
	description = "This rule detects something"

	strings:
		$a = "SHA1-Digest: D1KOexBGmlpJS53iK7KjJcyzt7o="

	condition:
		all of them
		
}