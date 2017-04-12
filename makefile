all: lib_encrypt lib_decrypt

lib_encrypt: lib_encrypt.c
	javac *.java
	javah MyEncrypt
	gcc -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -shared -fpic -o libencrypt.so lib_encrypt.c
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.

lib_decrypt: lib_decrypt.c
	gcc -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -shared -fpic -o libdecrypt.so lib_decrypt.c
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.