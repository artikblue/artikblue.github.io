#include <stdio.h>
#include <stdlib.h>

struct students {
   int a[20];
   char  b[20];
};
 
int main( ) {
	time_t t;
	int i, n;
	srand((unsigned) time(&t));
	struct students s1;

	for( i = 0 ; i < 20 ; i++ ) {
	      s1.a[i] = rand() % 11;
	}

	for( i = 0 ; i < 20 ; i++ ) {
              printf("%d ",s1.a[i]);
        }

	return 0;
}
