#include <stdio.h>
#include <jni.h>
#include "MyEncrypt.h"

void decrypt (int* v, int* k);

JNIEXPORT void JNICALL Java_MyDecrypt_decrypt
  (JNIEnv *env, jobject object, jintArray v, jintArray k){
  	// decrypt(v,k);
  	jsize len;
	jint *myCopyv;
	jint *myCopyk;
	// // int right, left, idx;
	// jint *result;
	jboolean *is_copyv = 0;
	jboolean *is_copyk = 0;

	len = (*env)->GetArrayLength(env, v);
	myCopyv = (jint *) (*env)->GetIntArrayElements(env, v, is_copyv);
	myCopyk = (jint *) (*env)->GetIntArrayElements(env, k, is_copyk);
	// if (myCopy == NULL){
	// printf("Cannot obtain array from JVM\n");
	// exit(0);
	// }

	// // right = (int) len - 1;
	// // left = 0;
	// // idx = left / 2;

	decrypt(myCopyv, myCopyk);

	// // return result;

	// // encrypt(v, k);
	(*env)->ReleaseIntArrayElements(env, v,myCopyv, 0);
	(*env)->ReleaseIntArrayElements(env, k,myCopyk, 0);
	return;

 //    jintArray outJNIArray = (*env)->NewIntArray(env, len+1);
 //    if (NULL == outJNIArray) return NULL;
 //    (*env)->SetIntArrayRegion(env, outJNIArray, 0, len+1, result);
 //    // printf("insert sort finish \n");
 //    return outJNIArray;
  }


void decrypt (int* v, int* k){
/* TEA decryption routine */
unsigned int n=32, sum, y=v[0], z=v[1];
unsigned int delta=0x9e3779b9l;

	sum = delta<<5;
	while (n-- > 0){
		z -= (y<<4) + k[2] ^ y + sum ^ (y>>5) + k[3];
		y -= (z<<4) + k[0] ^ z + sum ^ (z>>5) + k[1];
		sum -= delta;
	}
	v[0] = y;
	v[1] = z;

	// return v;
}

