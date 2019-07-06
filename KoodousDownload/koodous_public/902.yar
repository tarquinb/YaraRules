rule RootApp
{
	meta:
		description = "Root app"
		
	strings:
		$a = "ROOT_ERROR_FAILED"
		$b = "STEP_EXECUTE"
	
	condition:
		all of them
}