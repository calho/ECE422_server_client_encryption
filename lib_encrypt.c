#include <stdio.h>
#include <jni.h>
#include "MyEncrypt.h"

void encrypt (int* v, int* k);

JNIEXPORT void JNICALL Java_MyEncrypt_encrypt
  (JNIEnv *env, jobject object, jintArray v, jintArray k){
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

	// result = encrypt(myCopy, k);

	// // return result;

	encrypt(myCopyv, myCopyk);
	(*env)->ReleaseIntArrayElements(env, v,myCopyv, 0);
	(*env)->ReleaseIntArrayElements(env, k,myCopyk, 0);
	return;
 //    jintArray outJNIArray = (*env)->NewIntArray(env, len+1);
 //    if (NULL == outJNIArray) return NULL;
 //    (*env)->SetIntArrayRegion(env, outJNIArray, 0, len+1, result);
 //    // printf("insert sort finish \n");
 //    return outJNIArray;

  }

void encrypt (int* v, int* k){
/* TEA encryption algorithm */
unsigned int y = v[0], z=v[1], sum = 0;
unsigned int delta = 0x9e3779b9, n=32;

	while (n-- > 0){
		sum += delta;
		y += (z<<4) + k[0] ^ z + sum ^ (z>>5) + k[1];
		z += (y<<4) + k[2] ^ y + sum ^ (y>>5) + k[3];
	}

	v[0] = y;
	v[1] = z;
	printf("v value after encryption %u\n",v[0] );
	// return v;
}

