import "androguard"
import "file"
import "cuckoo"


rule bitwise_antiskid : obfuscator
{
  meta:
    description = "Bitwise AntiSkid"

  strings:
    $credits = "AntiSkid courtesy of Bitwise\x00"
    $array = "AntiSkid_Encrypted_Strings_Courtesy_of_Bitwise"
    $truth1 = "Don't be a script kiddy, go actually learn something. Stealing credit is pathetic, you didn't make this or even contribute to it and you know it."
    $truth2 = "Only skids can't get plaintext. Credits to Bitwise.\x00"

  condition:
    any of them
}