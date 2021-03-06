
import "androguard"

import "file"

import "cuckoo"



rule bankingsha : versi0ne

{

    meta:

        description = "This rule detects Bankers that embed the sha of the name of the targets apps"

        sample = "89f537cb4495a50b082758b34e54bd1024463176d7d2f4a445cf859f5a33e38f"


    strings:

        $sha0 = /\*6923da13f02ffae80c6f70832f2259070e74e6fa\*/

        $sha1 = /\*eee004f5b9c0be27359f50434cf3c2286c55acb6\*/

        $sha2 = /\*afbd5d3030052e8328280cf64d8c4bf51618e834\*/

        $sha3 = /\*afbd5d3030052e8328280cf64d8c4bf51618e834\*/

        $sha4 = /\*55a32856f20c9308f3356bed69824c637573470e\*/

        $sha5 = /\*9b21860b33b584b1989c8a66a8b401399f3872fc\*/

        $sha6 = /\*108adc236d6d0d0b9e258034cb8521dbb6a3f49d\*/

        $sha7 = /\*31f6405d71e4981a3f481e272b2fb0d129afab74\*/

        $sha8 = /\*080ee48abd4d9465810b4202a2db7a83c58c9a19\*/

        $sha9 = /\*0cd98c682f4b747950ed2c99fce21d9615f5faff\*/

        $sha10 = /\*fba00c82addfc985f644bffc47e5cc91f848fe5a\*/

        $sha11 = /\*216cc127f3725aeca4fec4d6b949c0599943b1e8\*/

        $sha12 = /\*e422fee08d5ef5c3821918a8a19983b697f3dd7b\*/

        $sha13 = /\*8711726fbc188f32f4631cf6f9138321a5b3aa26\*/

        $sha14 = /\*bbd23e2a2efaec9bb3c94188f96c98fc3664737a\*/

        $sha15 = /\*a06e4e77b4ca42df6c40c5afea695e9547646382\*/

        $sha16 = /\*c2e9c76df4c8870ebb255e3678127ec096fbe062\*/

        $sha17 = /\*cf0a862bd64494dc17f44032c380cddf8d2460af\*/

        $sha18 = /\*7e74dd5494eda5018a35b9475b1de7e4e0a6f4f7\*/

        $sha19 = /\*49f0bf429ee56881914e68eebe0762c86e41eb94\*/

        $sha20 = /\*692c077d657d46d1610290f0741a1a4d56c894ac\*/

        $sha21 = /\*64d8de190db52183bb24bb126f54198219935ef4\*/

        $sha22 = /\*42824e8fc87d8a2db2dc6d558a68477a9a6b689f\*/

        $sha23 = /\*d746cab7a65a95d29129e30df0fb3b5a041af8ec\*/

        $sha24 = /\*c772315587ee785145bc89c18b2a9e6f5104adbc\*/

        $sha25 = /\*c9983fb804f335ab26560d12d63ccb76f2ac6ef2\*/

        $sha26 = /\*863deb33345866899c1753a122cf589700b42a89\*/

        $sha27 = /\*96ddcfe2372034c47c23fda50192b49defa620b8\*/

        $sha28 = /\*133a2be3a669067c29050134460eca4a2c5ce527\*/

        $sha29 = /\*7770044bfe02ea92a6408b5dfba0aed9b2be7307\*/

        $sha30 = /\*9a565bd6f8ee5d043aa387583873d3371098e85f\*/

        $sha31 = /\*ef21dade0db65fa83edf31c4ca5ce892040c0c5b\*/

        $sha32 = /\*bdee232556f59ddc2177040162711a31605f25f7\*/

        $sha33 = /\*1c5acb8a30e3026da47aaee1510fafe1d379efdf\*/

        $sha34 = /\*562994ca64167e07817199b2c5f308db699b0d03\*/

        $sha35 = /\*5fa6f3e91ce437230a34bcca56f5e6d7d11ee06d\*/

        $sha36 = /\*ee9792ee5ed4de0d6a1ad44c65525aa7818e989f\*/

        $sha37 = /\*03d7999570c558cfcedee1c683ac63ecabbb39eb\*/

        $sha38 = /\*b1e6c9899dc77069aabfd8a1154c471fe0037b67\*/

        $sha39 = /\*37b556e482ded4ca459d58093b9fed688efc0eff\*/

        $sha40 = /\*a57104e5fce59bc45fb3835265c98328a491c077\*/

        $sha41 = /\*e7745b64f8ef2106b01fc0a05ab252a2eb23f688\*/

        $sha42 = /\*9821fe9c0b6a16317329672489b503bc548fcaf9\*/

        $sha43 = /\*18ff8391a04b1878cb88104d13761504455a18cd\*/

        $sha44 = /\*1e488fc038e98b2ab2e609983877ce6354120e4d\*/

        $sha45 = /\*a33e1e3f8decef7752b0f70526282d566cf5d83f\*/

        $sha46 = /\*67b0548291ee4fbec6d9e6694784e85ec79f7a9a\*/

        $sha47 = /\*fca863c4c30b3498386a73962a5f1b1ea86779c8\*/

        $sha48 = /\*1eb85abcf24ba0fb80e6e04d30f3b41da1f87d31\*/

        $sha49 = /\*a5b5c44fceef5ecd4e46a783cc7f54ba78e0e3ac\*/

        $sha50 = /\*3b315d6468d0907abb2cb8a4111ec64d5dfd073d\*/

        $sha51 = /\*d5c79e7bc7263c2fa06e0d68919f7ff608cc7b03\*/

        $sha52 = /\*dcedfe360ee2e0c8c274bfcf78dba28d53787ce1\*/

        $sha53 = /\*77f10a83501449d025a6d24d51ab5304b4c8548f\*/

        $sha54 = /\*1b4b6620f3f53f98d7cc8b80627989df36bc1d86\*/

        $sha55 = /\*ae590c0571afa9bb3dc99e774017ef6bd61452cb\*/

        $sha56 = /\*b337169cfb4de095c1d368776dc110d991440691\*/

        $sha57 = /\*ed3b23140e2a559b7d9e982c9de08dbf653c0910\*/

        $sha58 = /\*e4cc9dc914668ac18aa568e1c08129a28381b9df\*/

        $sha59 = /\*ed98c14b028ab1e35b6fbc5555b25c3e597998d5\*/

        $sha60 = /\*d11f06f0a5709f2272aeaec3de189427d9da3686\*/

        $sha61 = /\*b78dd8f0977eaf3eec4de326e2ba089d59444fa9\*/

        $sha62 = /\*58986e9915af4dfdd8e7f9228c95457fb03b528b\*/

        $sha63 = /\*9165a9c67a4b509b07fe8b155090b7b012fa471b\*/

        $sha64 = /\*7d1c35e47456a08bd8246bcec1654ceec4499eb4\*/

        $sha65 = /\*cb6b8e19979f6c79360021a5b93c3665b9bbae6a\*/

        $sha66 = /\*800603322b1825e416f5bfc4125b26b075a57603\*/

        $sha67 = /\*d7ef30fa72c8a7c4fa83f69d87e829f411c9eb8f\*/

        $sha68 = /\*820ab154fbb064a54ffedbf5fc29791c40135695\*/

        $sha69 = /\*41848c7c6c1eeaaa13f5ea3dec46e199929289cf\*/

        $sha70 = /\*3fc861fb56860106a2b295244ac06e9fbec51d99\*/

        $sha71 = /\*ffe079dc7f3954f1ee5cb938b5195b9713b9fccc\*/

        $sha72 = /\*c997beaef53027222e1be15f21657ae1d3a67dc5\*/

        $sha73 = /\*b90935e573dcfcfe7c677622a515894b66ed39e2\*/

        $sha74 = /\*6ff0c1dc9663b75532417cea43ef385bb1476f0c\*/

        $sha75 = /\*fc4b663c09eae08d8778299905f617087d00cc65\*/

        $sha76 = /\*2ff85b56d837f61d68683447e35c4ea8653a58c2\*/

        $sha77 = /\*cc78fa62e111139d017998b488ea0a3f78eb1f1f\*/

        $sha78 = /\*4182c05028c14b61bffa9d70e60197b0d93df8d4\*/

        $sha79 = /\*e1762dc93654ffa57ab63e6f234ddad60ad33c5e\*/

        $sha80 = /\*66787254569b68970bf7cafc13e0f61aff9759a8\*/

        $sha81 = /\*b30ad7be60b6f556f5982b02f4779609fd68b73c\*/

        $sha82 = /\*2f3c00be0741322af5262f514eebb623d2de5142\*/

        $sha83 = /\*dd6bfdc328017b193160a9a9ff34a3dfa6e67dac\*/

        $sha84 = /\*1e888820524341c3ea40cddc859572165cad2654\*/

        $sha85 = /\*4c2b6b2cbd929dad845adaefffe4e5fb04c66581\*/

        $sha86 = /\*d9692ba3357042fd448bece301043b06a97057ae\*/

        $sha87 = /\*938699a8db8726b779eed1515572598b463d2b71\*/

        $sha88 = /\*4075376f01a344b7517c2588afe180160137fb4a\*/

        $sha89 = /\*e8b1c38298f0df89d6aa9a40d4f63fd08c5e3318\*/

        $sha90 = /\*d7e653342bf503c770d4a142cff53cc83738a3f1\*/

        $sha91 = /\*4bb11a5a24771e69698d1ad579c5b5805a07ef00\*/

        $sha92 = /\*dff7ecc6491beb5f19ed879a14586d184c364e12\*/

        $sha93 = /\*2acdc7f3292d5c5723c478f853442b087b322c0b\*/

        $sha94 = /\*fc8226b5c465b03f9410ef13ea2b1fefa3ee352f\*/

        $sha95 = /\*da6335156f81b56a57b91ec7b8ab24dabaea36c3\*/

        $sha96 = /\*c6ffdc26b44df0a702e97f5c9f9e66b282f9d08d\*/

        $sha97 = /\*2dfd84944fbb2dba259bc409acbee36e9d7c1df8\*/

        $sha98 = /\*a6cb1edbb8c5ca7caadd2a35d3ef3eed4ab2fada\*/

        $sha99 = /\*9f5ba21341fea5d4e2555e3a29bf0dfbfdc23943\*/

        $sha100 = /\*1347cc87c68b0addaeb9e6402fe5b4b7dabe981e\*/

        $sha101 = /\*a9aef1f64d83634f1c474bcd42a5281cb92518f7\*/

        $sha102 = /\*e9d955fe2f16321b5232a1bb900a83fd84c89bec\*/

        $sha103 = /\*602ab4c4ac00b6ddff3b701b0d81018bebcfd081\*/

        $sha104 = /\*5f3a7a5394d04276d288577ccce25e80c208e343\*/

        $sha105 = /\*605b762b1bb4d5ab9376344160a47c9f1f2e175b\*/

        $sha106 = /\*fc94ce267241f124e7b176aae04816b34cbdf935\*/

        $sha107 = /\*20522969eaf14e2b517949d460338eafc3ca9bfc\*/

        $sha108 = /\*59817a51c39036a39988561925b591f4b2bbdf1f\*/

        $sha109 = /\*bb3f33bac710195dbd839157d9d8acc48bb840c6\*/

        $sha110 = /\*c6e058047efee823fae0891af90c398b040684ef\*/

        $sha111 = /\*12ee6977aa19b44b66cde50f6a5e9e3987d137ef\*/

        $sha112 = /\*021a6d96c2558913788ae3c6130fa492a48083dc\*/

        $sha113 = /\*85546c4a110ec46749bc75da5dc5e691612d9af4\*/

        $sha114 = /\*b72fe614a84a6d986279cedf66437f66e57752bf\*/

        $sha115 = /\*a0a4e2ca9f49bd1cdf2fd5188a4735ad8bf8f14d\*/

        $sha116 = /\*3646d39a3ee6f54a19106da0bd5e16675ceea750\*/

        $sha117 = /\*7b88382ab6bd24ba597e07ce9a52c980cd4295bf\*/

        $sha118 = /\*3da4b14def0493218bca6c2b0132df5f59851e7d\*/

        $sha119 = /\*bb13ee4d8e21fc41a68ef940ddb7282ad127712d\*/

        $sha120 = /\*87148e1723083e2fad0c56e0ca8b9e9d99967c0f\*/

        $sha121 = /\*71d1897d14097558631f287ff9575a43fe7fa699\*/

        $sha122 = /\*f4c94c82e64192660791a7285331829a68994f75\*/

        $sha123 = /\*634bd3f14ce65c8e5ccb33d3ab29bf8b463530b5\*/

        $sha124 = /\*6fb8d5fdbe98048d7935797c2d8ce055b2d30cb7\*/

        $sha125 = /\*9dde70da2dea57da254132cc2d1e17d4b5a9399c\*/

        $sha126 = /\*828b8ab597d958f153a270a7f4a1bbf65a39e9ce\*/

        $sha127 = /\*024729b5a3df67e7708e3067b1fd47bae2145271\*/

        $sha128 = /\*45d13d6041a4869b38d44dfd2c21a3b69479cb83\*/

        $sha129 = /\*94a35b8abb99100be94f7f96cf54c2b80c90cb12\*/

        $sha130 = /\*801c8bd1e8edc6eda384c65aaa748102472416ce\*/

        $sha131 = /\*4df35cb2a4b1ce6c0dab545908137d265ae72622\*/


    condition:

        any of them


}