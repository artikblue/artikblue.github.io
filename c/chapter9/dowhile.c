#include <stdio.h>
 
main() {
  int data[100];      
  int entered;    
  int i;           
  long sum=0;     
 
  do {
    printf("How many numbers? ");
    scanf("%d", &entered);
    if (entered>100)  
      printf("Limit is 100");
  } while (entered>100);  
 
  
  for (i=0; i<entered; i++) {
    printf("Enter number %d: ", i+1);
    scanf("%d", &data[i]);
  }
 
  
  for (i=0; i<entered; i++) 
    sum += data[i];
 
  printf("SUM: %ld\n", sum);
}
