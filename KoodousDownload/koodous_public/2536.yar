import "androguard"


rule Marcher_ObfuscatedStr
{
	meta:
		description = "This rule detects hardcoded strings in marcher malware using regex built to detect their string obfuscation scheme. Strings are obfuscated with each character being delimited by (** or <<) 3 random chars (** or >>) and these characters vary for each apk"
		sample = "8e9bdb1f5a37471f3f50cc9d482ea63c377e84b73d9bae6d4f37ffe403b9924e"

	strings:
		$a = /A(\*{2}|<{2})\w{3}(\*{2}|>{2})c(\*{2}|<{2})\w{3}(\*{2}|>{2})c(\*{2}|<{2})\w{3}(\*{2}|>{2})o(\*{2}|<{2})\w{3}(\*{2}|>{2})u(\*{2}|<{2})\w{3}(\*{2}|>{2})n(\*{2}|<{2})\w{3}(\*{2}|>{2})t/
		$b = /C(\*{2}|<{2})\w{3}(\*{2}|>{2})a(\*{2}|<{2})\w{3}(\*{2}|>{2})r(\*{2}|<{2})\w{3}(\*{2}|>{2})d/
		$c = /C(\*{2}|<{2})\w{3}(\*{2}|>{2})o(\*{2}|<{2})\w{3}(\*{2}|>{2})n(\*{2}|<{2})\w{3}(\*{2}|>{2})n(\*{2}|<{2})\w{3}(\*{2}|>{2})e(\*{2}|<{2})\w{3}(\*{2}|>{2})c(\*{2}|<{2})\w{3}(\*{2}|>{2})t/
	condition:
		$a or
		$b or
		$c
		
}