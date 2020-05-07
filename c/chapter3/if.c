#include <stdio.h>


func2(){
int num;
printf("Enter a number: ");
scanf("%d", &num);

if(num>0) printf("The number is positive.\n");

getchar();
}


main(){

func2();
getchar();


}
