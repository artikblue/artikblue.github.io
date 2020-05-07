# include <stdio.h>

main(){
 func();
 getchar();
  getchar();     
}

func(){

    char text[40];        

    printf("Your name: ");
    scanf("%s", text);
    printf("Hi, %s. First letter: %c\n", text, text[0]);
	}

