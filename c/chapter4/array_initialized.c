# include <stdio.h>

main(){
 func();
 getchar();     
}

func(){

    int sum=0;
    int i;

    int num[5] ={200, 150, 100, -50, 300};


	for(i=0;i<=4;i++) sum += num[i]; 
    printf("SUM is %d", sum);
	}


