#include <jni.h>

#include <cpuid.h>
#include <stdint.h>


JNIEXPORT jboolean JNICALL Java_com_github_marschall_hardwareacceleratedsha_HardwareSHA_isSupported0
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