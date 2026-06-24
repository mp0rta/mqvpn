# JNI downcall: NativeBridge の native メソッド名 (静的 JNI 名で解決)
-keepclasseswithmembernames class **.NativeBridge { native <methods>; }

# JNI upcall: GetMethodID で文字列名解決される callback (mqvpn_jni.c:450-466)
-keep class **.TunnelCallbacks { *; }
-keepclassmembers class * implements **.TunnelCallbacks {
    void onNative*(...);
}
