rule Moreclasses : findingfiles
{
	meta:
		description = "This rule detects if the app contains more than one classes file."

	strings:
		$a = "classes2.dex"
		$b = "classes3.dex"

	condition:
		any of them
}