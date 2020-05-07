#include <stdio.h>
#include <stdlib.h>

int main(){

    int i = 2;

    char c = 'c';

    char* pc = &c;

    printf("%p \n",&i);
    printf("%p \n",&c);

    printf("%c \n",c);
    return 0;
}