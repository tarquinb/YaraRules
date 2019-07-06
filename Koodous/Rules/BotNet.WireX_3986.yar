rule WireX
{
	strings:
		$ = "g.axclick.store"
		$ = "ybosrcqo.us"
		$ = "u.axclick.store"
    	$ = "p.axclick.store"

	condition:
		1 of them
		
}