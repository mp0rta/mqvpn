# JNI downcall: NativeBridge native method names (resolved by static JNI names)
-keepclasseswithmembernames class **.NativeBridge { native <methods>; }

# JNI upcall: callbacks resolved by string name through GetMethodID (mqvpn_jni.c:450-466)
-keep class **.TunnelCallbacks { *; }
-keepclassmembers class * implements **.TunnelCallbacks {
    void onNative*(...);
}

# JNI upcall: PlatformTrust.verify is resolved by literal name in JNI_OnLoad
# (mqvpn_jni.c). Keep exactly that member; the internal helpers stay strippable.
-keep class com.mqvpn.sdk.native_.PlatformTrust
-keepclassmembers class com.mqvpn.sdk.native_.PlatformTrust {
    public static java.lang.String verify(byte[][], java.lang.String);
}
