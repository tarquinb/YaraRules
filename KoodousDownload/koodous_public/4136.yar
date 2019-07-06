import "androguard"
import "file"
import "cuckoo"


rule CNProtect_dex : protector
{
  // https://github.com/rednaga/APKiD/issues/52
  meta:
    description = "CNProtect (anti-disassemble)"
    example = "5bf6887871ce5f00348b1ec6886f9dd10b5f3f5b85d3d628cf21116548a3b37d"

  strings:
    // code segment of the injected methods plus junk opcodes
    $code_segment = {
	  02 00 01 00 00 00 00 00 ?? ?? ?? ?? 11 00 00 00 00 (1? | 2? | 3? | 4? | 5? | 6? | 7? | 8? | 9? | a? | b? | c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7)
    }

  condition:
    $code_segment
}