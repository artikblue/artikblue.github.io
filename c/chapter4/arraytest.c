# include <stdio.h>

main(){
 func();
 getchar();     
}

func(){

    int sum=0;
    int i;

    int num[] ={20, 15, 10, 50, 31};


	for(i=0;i<=4;i++) sum += num[i]; 
    printf("SUM is %d", sum);
	}


