import "androguard"
import "file"
import "cuckoo"

/*
http://www.freebuf.com/articles/terminal/150360.html
*/
rule GhostFrameWork_EventDex
{
	strings:
		$a = "EventDex"

	condition:
		$a		
}