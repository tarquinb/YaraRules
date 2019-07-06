import "androguard"
import "file"
import "cuckoo"

/*
 * Copyright (C) 2017  RedNaga. http://rednaga.io
 * All rights reserved. Contact: rednaga@protonmail.com
 *
 *
 * This file is part of APKiD
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial APKiD licenses may use this file
 * in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and RedNaga.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of this
 * file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 * information to ensure the GNU General Public License version 3.0
 * requirements will be met.
 *
 **/



rule appguard : packer
{
  meta:
    description = "AppGuard"
    // http://appguard.nprotect.com/en/index.html

  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"

  condition:
    ($stub and $encrypted_dex)
}

rule dxshield : packer
{
  meta:
    description = "DxShield"
    // http://www.nshc.net/wp/portfolio-item/dxshield_eng/

  strings:
    $decryptlib = "libdxbase.so"
    $res = "assets/DXINFO.XML"

  condition:
    ($decryptlib and $res)
}

rule secneo : packer
{
  meta:
    description = "SecNeo"
    // http://www.secneo.com

  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"

  condition:
    any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}

rule dexprotector : packer
{
 /**
 * DexProtector v6.x.x :- Demo,Standard,Business Edition (https://dexprotector.com)
 **/
  meta:
    author = "Jasi2169"
    description = "DexProtector"

  strings:
    $encrptlib = "assets/dp.arm.so.dat"
    $encrptlib1 = "assets/dp.arm-v7.so.dat"
    $encrptlib2 = "assets/dp.arm-v8.so.dat"
    $encrptlib3 = "assets/dp.x86.so.dat"
    $encrptcustom = "assets/dp.mp3"

  condition:
    any of ($encrptlib, $encrptlib1, $encrptlib2, $encrptlib3) and $encrptcustom
}

rule apkprotect : packer
{
  meta:
    description = "APKProtect"

  strings:
    $key = "apkprotect.com/key.dat"
    $dir = "apkprotect.com/"
    $lib = "libAPKProtect.so"

  condition:
    ($key or $dir or $lib)
}

rule bangcle : packer
{
  meta:
    description = "Bangcle"

  strings:
    $main_lib = "libsecexe.so"
    $second_lib = "libsecmain.so"
    $container = "assets/bangcleplugin/container.dex"
    $encrypted_jar = "bangcleclasses.jar"
    $encrypted_jar2 = "bangcle_classes.jar"

  condition:
    any of ($main_lib, $second_lib, $container, $encrypted_jar, $encrypted_jar2)
}

rule kiro : packer
{
  meta:
    description = "Kiro"

  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"

  condition:
    $kiro_lib and $sbox
}

rule qihoo360 : packer
{
  meta:
    description = "Qihoo 360"

  strings:
    $a = "libprotectClass.so"

  condition:
    $a and
    not kiro
}

rule jiagu : packer
{
  meta:
    description = "Jiagu"
    //developed by Qihoo 360 http://jiagu.360.cn/

  strings:
    // These contain a trick function "youAreFooled"
    $main_lib = "libjiagu.so"
    $art_lib = "libjiagu_art.so"

  condition:
    ($main_lib or $art_lib)
}

rule qdbh_packer : packer
{
  meta:
    description = "'qdbh' (?)"

  strings:
    $qdbh = "assets/qdbh"

  condition:
    $qdbh
}

rule unknown_packer_lib : packer
{
  meta:
    description = "'jpj' packer (?)"

  strings:
    $pre_jar = { 00 6F 6E 43 72 65 61 74 65 00 28 29 56 00 63 6F 6D 2F 76 }
    $jar_data = { 2E 6A 61 72 00 2F 64 61 74 61 2F 64 61 74 61 2F 00 2F }
    $post_jar = { 2E 6A 61 72 00 77 00 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 00 67 65 74 49 6E 74 00 }

  condition:
    //is_apk and
    ($pre_jar and $jar_data and $post_jar)
}

rule unicom_loader : packer
{
  meta:
    description = "Unicom SDK Loader"

  strings:
    $decrypt_lib = "libdecrypt.jar"
    $unicom_lib = "libunicomsdk.jar"
    $classes_jar = "classes.jar"

  condition:
    ($unicom_lib and ($decrypt_lib or $classes_jar))
}

rule liapp : packer
{
  meta:
    description = "LIAPP"

  strings:
    $dir = "/LIAPPEgg"
    $lib = "LIAPPClient.sc"

  condition:
    any of ($dir, $lib)
}

rule app_fortify : packer
{
  meta:
    description = "App Fortify"

  strings:
    $lib = "libNSaferOnly.so"

  condition:
    $lib
}

rule nqshield : packer
{
  meta:
    description = "NQ Shield"

  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"

  condition:
    any of ($lib, $lib_sec1, $lib_sec2)
}

rule tencent : packer
{
  meta:
    description = "Tencent"

  strings:
    $decryptor_lib = "lib/armeabi/libshell.so"
    $zip_lib = "lib/armeabi/libmobisecy.so"
    $classpath = "com/tencent/StubShell"
    $mix_dex = "/mix.dex"

  condition:
    ($classpath or $decryptor_lib or $zip_lib or $mix_dex)
}

rule ijiami : packer
{
  meta:
    description = "Ijiami"

  strings:
    $old_dat = "assets/ijiami.dat"
    $new_ajm = "ijiami.ajm"
    $ijm_lib = "assets/ijm_lib/"

  condition:
    ($old_dat or $new_ajm or $ijm_lib)
}

rule naga : packer
{
  meta:
    description = "Naga"

  strings:
    $lib = "libddog.so"

  condition:
    $lib
}

rule alibaba : packer
{
  meta:
    description = "Alibaba"

  strings:
    $lib = "libmobisec.so"

  condition:
    $lib
}

rule medusah : packer
{
  meta:
    // https://medusah.com/
    description = "Medusah"

  strings:
    $lib = "libmd.so"

  condition:
    $lib
}

rule medusah_appsolid : packer
{
  meta:
    // https://appsolid.co/
    // Samples and discussion: https://github.com/rednaga/APKiD/issues/19
    description = "Medusah (AppSolid)"

  strings:
    $encrypted_dex = "assets/high_resolution.png"

  condition:
    $encrypted_dex and not medusah
}

rule baidu : packer
{
  meta:
    description = "Baidu"

  strings:
    $lib = "libbaiduprotect.so"
    $encrypted = "baiduprotect1.jar"

  condition:
    ($lib or $encrypted)
}

rule pangxie : packer
{
  // sample: ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c
  meta:
    description = "PangXie"

  strings:
    $lib = "libnsecure.so"

  condition:
    $lib
}

rule kony : packer
{
  meta:
    description = "Kony"
    // http://www.kony.com/

  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"

  condition:
    $lib and $decrypt_keys and $encrypted_js
}

rule approov : packer
{
  meta:
    description = "Aproov"
    // https://www.approov.io/

  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"

  condition:
    $lib and $sdk_config
}

rule yidun : packer
{
  meta:
    description = "yidun"
    // https://dun.163.com/product/app-protect

  strings:
    $anti_trick = "Lcom/_" // Class path of anti-trick
    $entry_point = "Lcom/netease/nis/wrapper/Entry"
    $jni_func = "Lcom/netease/nis/wrapper/MyJni"
    $lib = "libnesec.so"

  condition:
    (#lib > 1) or ($anti_trick and $entry_point and $jni_func)
}