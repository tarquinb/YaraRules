rule drop
{
	meta:
		description = "This rule detects references to other applications"

	strings:
		$a = "Landroid/os/FileObserver"

	condition:
		$a
}