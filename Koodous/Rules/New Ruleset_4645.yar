rule aamo_str_enc : obfuscator
{
  meta:
    description = "AAMO (String decryption function only)"
    author = "P0r0"
    url = "https://github.com/necst/aamo"

  strings:
    $opcodes = {
        22 ?? ?? ??
        12 22
        1a ?? ?? ??
        71 ?? ?? ?? ?? ??
        0c 02
        71 ?? ?? ?? ?? ??
        0c 03
        6e ?? ?? ?? ?? ??
        0c 02
        1a ?? ?? ??
        70 ?? ?? ?? ?? ??
        71 ?? ?? ?? ?? ??
        0c 04
    }
    $a = { 00 0f 63 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 00 } // convertToString
    $b = { 00 14 67 65 74 53 74 6f 72 61 67 65 45 6e 63 72 79 70 74 69 6f 6e 00 } //getStorageEncryption

  condition:
    $opcodes and
    all of ($a, $b)
}