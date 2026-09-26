# R8 rules for the release build

# The database model is (de)serialized by Jackson through reflection: keep the classes with their constructors,
# fields and accessors (Lombok-generated), and the annotations and generic signatures Jackson reads.
-keep class at.yawk.password.model.** { *; }
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations

# Jackson 3 instantiates its (de)serializers and modules reflectively and reads its own annotations.
-keep class tools.jackson.databind.** { *; }
-keep class tools.jackson.core.** { *; }
-keep @interface com.fasterxml.jackson.annotation.** { *; }
-keep class com.fasterxml.jackson.annotation.** { *; }
# optional integrations (java.beans, JDK XML types, ...) that don't exist on Android
-dontwarn tools.jackson.databind.ext.**
-dontwarn java.beans.**

# BouncyCastle is only called directly (SCrypt), so it can be shrunk. Some of its classes refer to JDK APIs that
# Android lacks (JNDI/LDAP, javax.naming); they are never used here.
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# optional compile-time annotations
-dontwarn org.jetbrains.annotations.**
-dontwarn lombok.**
