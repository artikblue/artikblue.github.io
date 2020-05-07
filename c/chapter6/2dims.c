# include <stdio.h>

main(){

 func();    
 getchar();
}

func(){
  int marks[2][10] = 
     { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
       11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

 
  printf("Mark related to third student on first group %d",
    marks[0][2]);
  printf("Mark related to third student on second group %d",
    marks[1][2]);

}
