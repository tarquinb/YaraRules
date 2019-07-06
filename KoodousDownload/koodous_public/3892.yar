import "androguard"
import "file"
import "cuckoo"


rule rootbeer : anti_root
{

	strings:
		$rb = "Lcom/scottyab/rootbeer/RootBeerNative;"
		$cls = "RootBeerNative"
		$str = "tool-checker"

	condition:
		all of them
}