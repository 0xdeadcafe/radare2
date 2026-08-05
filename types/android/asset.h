/*
 * Android Asset Manager type definitions for radare2
 *
 * Usage: to types/android/asset.h
 *        ts AAsset
 *        te asset_mode
 *
 * Used for native code that accesses APK assets.
 */

/* Asset access modes */
enum asset_mode {
    AASSET_MODE_UNKNOWN   = 0,
    AASSET_MODE_RANDOM    = 1,
    AASSET_MODE_STREAMING = 2,
    AASSET_MODE_BUFFER    = 3
};

/* Asset functions */
void *AAssetManager_fromJava(void *env, void *assetManager);
void *AAssetManager_open(void *mgr, char *filename, int mode);
void *AAssetManager_openDir(void *mgr, char *dirName);

void AAsset_close(void *asset);
int AAsset_read(void *asset, void *buf, int count);
long AAsset_seek(void *asset, long offset, int whence);
long AAsset_seek64(void *asset, long offset, int whence);
long AAsset_getLength(void *asset);
long AAsset_getLength64(void *asset);
long AAsset_getRemainingLength(void *asset);
long AAsset_getRemainingLength64(void *asset);
void *AAsset_getBuffer(void *asset);
int AAsset_isAllocated(void *asset);
int AAsset_openFileDescriptor(void *asset, void *outStart, void *outLength);
int AAsset_openFileDescriptor64(void *asset, void *outStart, void *outLength);

char *AAssetDir_getNextFileName(void *assetDir);
void AAssetDir_rewind(void *assetDir);
void AAssetDir_close(void *assetDir);
