# include <stdio.h>

main(){
 func();
 getchar();
  getchar();     
}

func(){

    char text[40];        

    printf("Name?: ");
    scanf("%s", text);
    printf("Hey, %s. First letter: %c\n", text, text[0]);
    printf("Ho, %s. Second letter: %c\n", text, text[1]);
	}

