/*
 * JNI (Java Native Interface) type definitions for radare2
 *
 * Usage: to types/android/jni.h
 *        ts JNINativeMethod
 *        te JNIVersion
 *
 * These are the core types needed for analyzing Android native libraries.
 * Based on NDK jni.h definitions.
 */

/* JNI version constants */
enum JNIVersion {
    JNI_VERSION_1_1 = 0x00010001,
    JNI_VERSION_1_2 = 0x00010002,
    JNI_VERSION_1_4 = 0x00010004,
    JNI_VERSION_1_6 = 0x00010006,
    JNI_VERSION_1_8 = 0x00010008,
    JNI_VERSION_9   = 0x00090000,
    JNI_VERSION_10  = 0x000a0000,
    JNI_VERSION_19  = 0x00130000,
    JNI_VERSION_20  = 0x00140000,
    JNI_VERSION_21  = 0x00150000
};

/* JNI return codes (r2 doesn't support negative enums, use defines mentally) */
enum JNIReturnCode {
    JNI_OK        = 0,
    JNI_ERR       = 0xffffffff,
    JNI_EDETACHED = 0xfffffffe,
    JNI_EVERSION  = 0xfffffffd,
    JNI_ENOMEM    = 0xfffffffc,
    JNI_EEXIST    = 0xfffffffb,
    JNI_EINVAL    = 0xfffffffa
};

/* JNI boolean values */
enum JNIBoolean {
    JNI_FALSE = 0,
    JNI_TRUE  = 1
};

/* JNI commit/abort modes for array functions */
enum JNIArrayMode {
    JNI_COMMIT = 1,
    JNI_ABORT  = 2
};

/* JNINativeMethod - used in RegisterNatives */
struct JNINativeMethod {
    char *name;
    char *signature;
    void *fnPtr;
};

/*
 * JNI reference types (opaque pointers)
 * In actual JNI these are different types, but for r2 analysis
 * we treat them as void* since we can't see the Java object internals
 */

/* JNI function table - partial, most commonly used functions */
/* Note: Full JNIEnv has 230+ function pointers */

/* JNI_OnLoad / JNI_OnUnload signatures */
int JNI_OnLoad(void *vm, void *reserved);
void JNI_OnUnload(void *vm, void *reserved);

/* Common JNIEnv functions (called through env pointer) */
/* These help identify JNI calls in disassembly */

int GetVersion(void *env);
void *DefineClass(void *env, char *name, void *loader, char *buf, int len);
void *FindClass(void *env, char *name);
void *FromReflectedMethod(void *env, void *method);
void *FromReflectedField(void *env, void *field);
void *ToReflectedMethod(void *env, void *cls, void *methodID, char isStatic);
void *GetSuperclass(void *env, void *sub);
char IsAssignableFrom(void *env, void *sub, void *sup);
void *ToReflectedField(void *env, void *cls, void *fieldID, char isStatic);
int Throw(void *env, void *obj);
int ThrowNew(void *env, void *clazz, char *msg);
void *ExceptionOccurred(void *env);
void ExceptionDescribe(void *env);
void ExceptionClear(void *env);
void FatalError(void *env, char *msg);
int PushLocalFrame(void *env, int capacity);
void *PopLocalFrame(void *env, void *result);
void *NewGlobalRef(void *env, void *lobj);
void DeleteGlobalRef(void *env, void *gref);
void DeleteLocalRef(void *env, void *obj);
char IsSameObject(void *env, void *obj1, void *obj2);
void *NewLocalRef(void *env, void *ref);
int EnsureLocalCapacity(void *env, int capacity);
void *AllocObject(void *env, void *clazz);
void *NewObject(void *env, void *clazz, void *methodID);
void *NewObjectV(void *env, void *clazz, void *methodID, void *args);
void *NewObjectA(void *env, void *clazz, void *methodID, void *args);
void *GetObjectClass(void *env, void *obj);
char IsInstanceOf(void *env, void *obj, void *clazz);
void *GetMethodID(void *env, void *clazz, char *name, char *sig);
void *GetFieldID(void *env, void *clazz, char *name, char *sig);
void *GetStaticMethodID(void *env, void *clazz, char *name, char *sig);
void *GetStaticFieldID(void *env, void *clazz, char *name, char *sig);

/* String operations */
void *NewString(void *env, void *unicode, int len);
int GetStringLength(void *env, void *str);
void *GetStringChars(void *env, void *str, char *isCopy);
void ReleaseStringChars(void *env, void *str, void *chars);
void *NewStringUTF(void *env, char *utf);
int GetStringUTFLength(void *env, void *str);
char *GetStringUTFChars(void *env, void *str, char *isCopy);
void ReleaseStringUTFChars(void *env, void *str, char *chars);

/* Array operations */
int GetArrayLength(void *env, void *array);
void *NewObjectArray(void *env, int len, void *clazz, void *init);
void *GetObjectArrayElement(void *env, void *array, int index);
void SetObjectArrayElement(void *env, void *array, int index, void *val);
void *NewBooleanArray(void *env, int len);
void *NewByteArray(void *env, int len);
void *NewCharArray(void *env, int len);
void *NewShortArray(void *env, int len);
void *NewIntArray(void *env, int len);
void *NewLongArray(void *env, int len);
void *NewFloatArray(void *env, int len);
void *NewDoubleArray(void *env, int len);
void *GetBooleanArrayElements(void *env, void *array, char *isCopy);
void *GetByteArrayElements(void *env, void *array, char *isCopy);
void *GetCharArrayElements(void *env, void *array, char *isCopy);
void *GetShortArrayElements(void *env, void *array, char *isCopy);
void *GetIntArrayElements(void *env, void *array, char *isCopy);
void *GetLongArrayElements(void *env, void *array, char *isCopy);
void *GetFloatArrayElements(void *env, void *array, char *isCopy);
void *GetDoubleArrayElements(void *env, void *array, char *isCopy);
void ReleaseBooleanArrayElements(void *env, void *array, void *elems, int mode);
void ReleaseByteArrayElements(void *env, void *array, void *elems, int mode);
void ReleaseCharArrayElements(void *env, void *array, void *elems, int mode);
void ReleaseShortArrayElements(void *env, void *array, void *elems, int mode);
void ReleaseIntArrayElements(void *env, void *array, void *elems, int mode);
void ReleaseLongArrayElements(void *env, void *array, void *elems, int mode);
void ReleaseFloatArrayElements(void *env, void *array, void *elems, int mode);
void ReleaseDoubleArrayElements(void *env, void *array, void *elems, int mode);

/* Region operations */
void GetBooleanArrayRegion(void *env, void *array, int start, int len, void *buf);
void GetByteArrayRegion(void *env, void *array, int start, int len, void *buf);
void GetCharArrayRegion(void *env, void *array, int start, int len, void *buf);
void GetShortArrayRegion(void *env, void *array, int start, int len, void *buf);
void GetIntArrayRegion(void *env, void *array, int start, int len, void *buf);
void GetLongArrayRegion(void *env, void *array, int start, int len, void *buf);
void GetFloatArrayRegion(void *env, void *array, int start, int len, void *buf);
void GetDoubleArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetBooleanArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetByteArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetCharArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetShortArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetIntArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetLongArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetFloatArrayRegion(void *env, void *array, int start, int len, void *buf);
void SetDoubleArrayRegion(void *env, void *array, int start, int len, void *buf);

/* Native method registration */
int RegisterNatives(void *env, void *clazz, void *methods, int nMethods);
int UnregisterNatives(void *env, void *clazz);

/* Monitor operations */
int MonitorEnter(void *env, void *obj);
int MonitorExit(void *env, void *obj);

/* JavaVM operations */
int GetJavaVM(void *env, void *vm);

/* String region operations */
void GetStringRegion(void *env, void *str, int start, int len, void *buf);
void GetStringUTFRegion(void *env, void *str, int start, int len, char *buf);

/* Primitive array critical access */
void *GetPrimitiveArrayCritical(void *env, void *array, char *isCopy);
void ReleasePrimitiveArrayCritical(void *env, void *array, void *carray, int mode);

/* String critical access */
void *GetStringCritical(void *env, void *string, char *isCopy);
void ReleaseStringCritical(void *env, void *string, void *cstring);

/* Weak global references */
void *NewWeakGlobalRef(void *env, void *obj);
void DeleteWeakGlobalRef(void *env, void *ref);

/* Exception check */
char ExceptionCheck(void *env);

/* Direct buffer operations */
void *NewDirectByteBuffer(void *env, void *address, long capacity);
void *GetDirectBufferAddress(void *env, void *buf);
long GetDirectBufferCapacity(void *env, void *buf);

/* Object reference type */
int GetObjectRefType(void *env, void *obj);
