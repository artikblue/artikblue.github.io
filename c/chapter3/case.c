#include <stdio.h>

func2(){
printf("Enter a key and then press enter: ");
char key;
scanf("%c",&key);

switch(key){
case ' ':
	printf("Space. \n");
	break;
case '1':
case '2':
case '3':
case '4':
case '5':
case '6':
case '7':
case '8':
case '9':
case '0': printf("Digit.\n");
break;
default: printf("Neither space nor digit.\n");
}

}

main(){
func2();
getchar();
}
