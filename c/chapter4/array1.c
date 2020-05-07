# include <stdio.h>

main(){
 funcion();
 getchar();     
}

funcion(){


    int num[5];           /* Un array de 5 números enteros */
    int sum;                /* Un entero que será la suma */

    num[0] = 200;      /* Les damos valores */
    num[1] = 150;
    num[2] = 100;
    num[3] = -50;
    num[4] = 300;
    sum = num[0] +    /* Y hallamos la suma */
        num[1] + num[2] + num[3] + num[4];
    printf("SUM IS %d", sum);

	}

