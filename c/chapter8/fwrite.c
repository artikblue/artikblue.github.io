#include <stdio.h>
#include <string.h>
main(){
func();
getchar();
}


func()
{ 
         
   FILE* ftest;
 
    ftest = fopen("test.txt", "wt");
    fputs("This is a line\n", ftest);
    fputs("Another line", ftest);
    fputs(" that follows the second line\n", ftest);
    fclose(ftest);

}

