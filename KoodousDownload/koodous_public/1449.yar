import "androguard"
import "file"
import "cuckoo"


rule fanta
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "commandObServer"
		$b = "ussd(): "
		$c = "const_id_send_sms"
		$d = "const_task_id_send_sms"

	condition:
		all of them
}