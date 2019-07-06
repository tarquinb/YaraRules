import "androguard"
import "file"
import "cuckoo"


rule frida : anti_hooks
{

	strings:
		$a = "frida-gum"
		$b = "frida-helper"
		$c = "re.frida.HostSession10"
		$d = "AUTH ANONYMOUS 474442757320302e31\\r\\n"
		$e = "re.frida"

	condition:
		any of them
}