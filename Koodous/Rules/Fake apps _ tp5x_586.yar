rule fake_apps
{
	meta:
		description = "Fake Apps"

	strings:
		$a = "150613072127Z"
		$b = "421029072127Z0I1"

	condition:
		$a or $b
}