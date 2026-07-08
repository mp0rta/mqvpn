# JNI downcall: NativeBridge native method names (resolved by static JNI names)
-keepclasseswithmembernames class **.NativeBridge { native <methods>; }

# JNI upcall: callbacks resolved by string name through GetMethodID (mqvpn_jni.c:450-466)
-keep class **.TunnelCallbacks { *; }
-keepclassmembers class * implements **.TunnelCallbacks {
    void onNative*(...);
}
