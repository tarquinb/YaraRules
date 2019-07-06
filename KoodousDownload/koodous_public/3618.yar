rule Androbot
{
	meta:
		description = "https://info.phishlabs.com/blog/bankbot-continues-its-evolution-as-agressivex-androbot"


	strings:
		$s1 = "/core/inject.php?type="
		$s2 = "/private/add_log.php"
		$s3 = "/core/functions.php "

	condition:
		2 of ($s*)
		
}