#include <jni.h>

#include <cpuid.h>
#include <stdint.h>


JNIEXPORT jboolean JNICALL Java_com_github_marschall_hardwareacceleratedsha_HardwareSha1_isSupported0
  (JNIEnv *env, jclass clazz)
{

    unsigned int eax, ebx, ecx, edx;
    unsigned int leaf, subleaf;

    leaf = 7;
    subleaf = 0;

    if (!__get_cpuid_count(leaf, subleaf, &eax, &ebx, &ecx, &edx))
    {
        return JNI_FALSE;
    }

    if ((ebx & bit_SHA) == bit_SHA)
    {
      return JNI_TRUE;
    }
    else
    {
      return JNI_FALSE;
    }
  }
}


JNIEXPORT jboolean JNICALL Java_com_github_marschall_hardwareacceleratedsha_HardwareSha1_processBlock0
  (JNIEnv *env, jclass clazz, jbyteArray input, jint offset, jintArray jstate)
{
    uint32_t state[5];
    uint8_t data[64];
    __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
    __m128i MSG0, MSG1, MSG2, MSG3;
    const __m128i MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);

    /* copy from Java to stack, this allows the GC to move the object */
    /* if we don't copy */
    /* either the JVM copies (to the heap) */
    /* or it has to pin the object */
    (*env)->GetIntArrayRegion(env, jstate, 0, 5, state);
    if (((*env)->ExceptionCheck(env)) == JNI_TRUE)
    {
        return -1;
    }
    (*env)->GetByteArrayRegion(env, input, 0, 5, data);
    if (((*env)->ExceptionCheck(env)) == JNI_TRUE)
    {
        return -1;
    }

    /* Load initial values */
    ABCD = _mm_loadu_si128((const __m128i*) state);
    E0 = _mm_set_epi32(state[4], 0, 0, 0);
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
}
