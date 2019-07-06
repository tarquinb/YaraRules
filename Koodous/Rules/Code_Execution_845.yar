import "androguard"


rule Code_Execution : official
{
	meta:
		description = "Ejecucion de codigo"
		

	strings:
		$a = "java/lang/Runtime"
		$b = "exec"

	condition:
		$a and $b
		
}