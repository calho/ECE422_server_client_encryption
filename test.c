#include <stdio.h>

/* function to generate and return random numbers */
void getRandom(int* v ) {

	int y = v[0], z = v[1];

	y = y+1;
	z = z+2;

	v[0] = y;
	v[1] = z; 

   // return v;
}

/* main function to call above defined function */
int main () {

   /* a pointer to an int */
   int v[2];
   int i;
   int *n;

   v[0] = 1;
   v[1] = 1;

   printf( "seg fault here \n");

   for ( i = 0; i < 2; i++ ) {
      printf( "before *(v + %i) : %i\n", i, v[i]);
   }

   // n = getRandom(v);
   getRandom(v);
	
   for ( i = 0; i < 2; i++ ) {
      printf( "after *(v + %i) : %i\n", i, v[i]);
   }

   return 0;
}