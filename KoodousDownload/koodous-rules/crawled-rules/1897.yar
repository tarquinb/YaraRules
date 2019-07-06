
rule notcompatible : ccm

{

    meta:

        description = "This rule detects notcompatible android malware, using common code signature method"



    strings:

    $S_3_5272 = { 52 52 ?? 00 b1 62 71 10 ?? ?? 02 00 0c 00 52 52 ?? 00 b1 62 23 21 ?? 00 54 52 ?? 00 6e 10 ?? ?? 02 00 0c 02 12 03 52 54 ?? 00 b1 64 71 54 ?? ?? 62 31 6e 20 ?? ?? 10 00 5b 50 ?? 00 52 52 ?? 00 b1 62 59 52 ?? 00 0e 00 }

    $S_3_5438 = { 54 20 ?? 00 6e 20 ?? 00 30 00 54 20 ?? 00 54 21 ?? 00 6e 10 ?? ?? 01 00 0a 01 de 01 01 04 6e 20 ?? ?? 10 00 0e 00 }

    $S_3_1276 = { 12 03 52 42 ?? 00 b0 72 71 10 ?? ?? 02 00 0c 00 54 42 ?? 00 6e 20 ?? ?? 32 00 54 42 ?? 00 6e 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 20 00 23 71 ?? 00 71 57 ?? ?? 65 31 6e 20 ?? ?? 10 00 5b 40 ?? 00 52 42 ?? 00 b0 72 59 42 ?? 00 0e 00 }

    $S_3_7030 = { 70 10 ?? ?? 01 00 12 00 59 10 ?? 00 52 10 ?? 00 71 10 ?? ?? 00 00 0c 00 5b 10 ?? 00 0e 00 }

    $S_3_1240 = { 12 01 52 32 ?? 00 39 02 04 00 07 10 11 00 54 30 ?? 00 39 00 04 00 07 10 28 fa 54 02 ?? 00 32 42 f7 ff 54 00 ?? 00 28 f6 }

    $S_3_1a90 = { 1a 00 ?? ?? 6e 10 ?? 00 04 00 0c 01 6e 20 ?? ?? 10 00 0a 00 38 00 0c 00 22 00 ?? 00 1c 01 ?? 00 70 30 ?? 00 30 01 6e 20 ?? 00 03 00 1a 00 ?? ?? 6e 10 ?? 00 04 00 0c 01 6e 20 ?? ?? 10 00 0a 00 38 00 0c 00 22 00 ?? 00 1c 01 ?? 00 70 30 ?? 00 30 01 6e 20 ?? 00 03 00 0e 00 }

    $S_3_12150 = { 12 12 12 03 52 64 ?? 00 39 04 03 00 0e 00 54 60 ?? 00 12 01 38 00 fc ff 54 04 ?? 00 33 74 39 00 39 01 06 00 54 04 ?? 00 5b 64 ?? 00 54 04 ?? 00 39 04 04 00 5b 61 ?? 00 54 04 ?? 00 39 04 21 00 01 25 38 01 20 00 01 24 b5 54 38 04 05 00 12 04 5b 14 ?? 00 54 04 ?? 00 38 04 17 00 01 24 38 01 16 00 b5 42 38 02 06 00 54 02 ?? 00 5b 12 ?? 00 52 62 ?? 00 d8 02 02 ff 59 62 ?? 00 28 c8 01 35 28 e1 01 34 28 e2 01 34 28 eb 01 32 28 eb 07 01 54 00 ?? 00 28 c0 }

    $S_3_1272 = { 12 02 54 53 ?? 00 39 03 03 00 0f 02 54 53 ?? 00 1a 04 ?? ?? 6e 20 ?? 00 43 00 0c 00 1f 00 ?? 00 6e 10 ?? 00 00 00 0c 01 38 01 f1 ff 6e 10 ?? 00 01 00 0a 03 38 03 eb ff 6e 10 ?? 00 01 00 0a 02 59 52 ?? 00 12 12 28 e2 }



    condition:

        7 of them


}