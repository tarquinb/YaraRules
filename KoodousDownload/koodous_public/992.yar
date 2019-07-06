import "androguard"
import "file"

rule testing
{
	meta:
		description = "This rule is a test"
		
	strings:
		$a = "install"

	condition:
		all of them
		// androguard.package_name("com.rwatch") or
		// file.sha256("2a5dc60ae66bf1d59399d5953ac122d860d0748af6a86286010bbe68a9818773")
		
}