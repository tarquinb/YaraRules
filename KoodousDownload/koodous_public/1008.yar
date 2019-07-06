import "androguard"
import "file"

rule testing
{
	meta:
		description = "WhatsAPP stealer?"
		
	strings:
	  $b1 = "8d4b155cc9ff81e5cbf6fa7819366a3ec621a656416cd793"
	  $b2 = "1e39f369e90db33aa73b442bbbb6b0b9"
	  $b3 = "346a23652a46392b4d73257c67317e352e3372482177652c"
	condition:
		any of them

		
}