# Android Type Definitions

Type definitions for Android NDK reverse engineering.

## Files

| File | Content |
|------|---------|
| `jni.h` | JNI (Java Native Interface) types |
| `functions.h` | Common bionic libc function signatures |
| `log.h` | Android logging types and functions |
| `asset.h` | Android asset manager types |

## Usage

```r2
# Load JNI types
to types/android/jni.h

# Load bionic function signatures
to types/android/functions.h

# Load Android logging
to types/android/log.h

# List loaded types
ts          # structs
te          # enums
tf          # functions
```

## Notes

- Types use basic C types for r2 compatibility (int, char, void*)
- JNI types are critical for analyzing native Android libraries
- bionic libc is mostly POSIX-compatible; types/libc/ can supplement these
