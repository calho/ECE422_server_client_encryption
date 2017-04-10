#include <stdio.h>
#include <jni.h>
#include "MyEncrypt.h"

void encrypt (jintArray v, jintArray k);

JNIEXPORT void JNICALL Java_MyDecrypt_decrypt
  (JNIEnv *env, jobject object, jintArray v, jintArray k){
  	decrypt(v,k);
  }


void decrypt (jintArray v, jintArray k){
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
}

