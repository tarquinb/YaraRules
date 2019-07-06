rule interesting_strings_1
{
meta:
 description = "Search for password string"
 author = "David Garcia"
 date = "2016-02-10"
 version = "1"
strings:
 $string_1 = { 64 72 6f 77 73 61 70 }
 $string_2 = "password"
condition:
 $string_1 or $string_2
}