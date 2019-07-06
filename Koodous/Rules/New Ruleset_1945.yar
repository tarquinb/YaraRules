rule demo2 
{
	meta:
		description = "demo"
		

	strings:
		$a = "Protected by Shield4J"
	    $b = "Spain1"
		$c = "Madrid1"
		$d = "Shield4J"

	condition:
		all of them		
}