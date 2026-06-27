# Strip all android.util.Log calls from release builds (no sensitive data, and
# removes the "Sensitive Data in Logs" static-analysis finding).
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}
