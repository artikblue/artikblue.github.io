#include <stdio.h>

func2(){
printf("Enter a key and then press enter: ");
int val;

printf("Select a fruit: \n");
printf("1: Apple\n");
printf("2: Orange\n");
printf("3: Banana\n");
printf("4: Pear\n");

scanf("%d",&val);

switch(val){
case 1:
	printf("Apple. \n");
	break;
case 2:
        printf("Orange. \n");
        break;
case 3:
        printf("Banana. \n");
        break;
case 4:
        printf("Pear. \n");
        break;

default: printf("Nothing selected.\n");
}

}

main(){
func2();
getchar();
}
