import "androguard"

rule Kasandra
{
	meta:
		author = "Tom_Sara"
		description = "This rule detects Kasandra"
		Sample= "b8db1fd7d8d3c7e42b26471756826d3d750749e676f38d9dd3f853f1b6a3cca8"

	strings:
		$a1 = "kryo"
		$a2 = "IFJDCS"
		$a3 = "WhatsApp/Databases"
		
	condition:
		all of them
		
}