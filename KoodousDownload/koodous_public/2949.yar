rule Dvmap
{
	meta:
		description = "This rule detects applications with Dvmap typical resource files: https://securelist.com/78648/dvmap-the-first-android-malware-with-code-injection/"
		sample = "183e069c563bd16219c205f7aa1d64fc7cb93c8205adf8de77c50367d56dfc2b"

	strings:
		$a = "Game321.res"
		$b = "Game322.res"
		$c = "Game323.res"
		$d = "Game324.res"
		$e = "Game64%d.res"

	condition:
		all of them
}