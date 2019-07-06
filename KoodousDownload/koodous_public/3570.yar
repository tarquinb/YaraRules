import "androguard"
import "file"
import "cuckoo"
import "droidbox"


rule sorter : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"

	condition:
		droidbox.written.filename(/EOZTzhVG.jar/) or
		droidbox.written.filename(/libus.so/)
}