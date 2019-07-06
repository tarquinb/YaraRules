rule WireX
{
	meta:
        description = "Evidences of WireX."
		sample = "168624d9d9368155b7601e7e488e23ddf1cd0c8ed91a50406484d57d15ac7cc3"

	strings:
		$1 = "axclick.store"
		$2 = "snewxwri"
   	condition:
    	1 of them
}