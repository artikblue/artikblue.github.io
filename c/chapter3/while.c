#include <stdio.h>

func2(){
int num;

printf("Enter a num, (exit with 0):");

scanf("%d", &num);

while(num != 0){

	if(num > 0) printf("Positive num\n");
	else printf("Negative num\n");

	printf("Enter another num (exit with 0):");

	scanf("%d", &num);

}

}



main(){

func2();
getchar();

}



