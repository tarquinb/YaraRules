rule aamo_str_enc_nop : obfuscator
{
  meta:
    description = "AAMO (String decryption function + interleaved NOPs)"
    author = "P0r0"
    url = "https://github.com/necst/aamo"
    example1 = "c1ef860af0e168f924663630ed3b61920b474d0c8b10e2bde6bfd3769dbd31a8"
    example2 = "eb0d4e1ba2e880749594eb8739e65aa21b6f7b43798f04b6681065b396c15a78"

  strings:
    $opcodes = {
        22 ?? ?? ?? 
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        12 22
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        1a ?? ?? ??
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        71 ?? ?? ?? ?? ??
        0c 02
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        71 ?? ?? ?? ?? ??
        0c 03
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        6e ?? ?? ?? ?? ??
        0c 02
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        1a ?? ?? ??
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
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