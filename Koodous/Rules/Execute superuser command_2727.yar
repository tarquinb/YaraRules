import "androguard"
import "file"
import "cuckoo"


rule SUexec
{
	meta:
		description = "Caution someone wants to execute a superuser command"
		

	strings:
		$a = "\"su\", \"-c\""
		$b ="su -c"

	condition:
		
		$a or $b		
}