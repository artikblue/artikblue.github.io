#include <stdio.h>
#include <stdlib.h>
 
main() {
  int* data;      
  int valnum;    
  int i;          
  long sum=0;     

  do {
    printf("How many vals you need to add? ");
    scanf("%d", &valnum);
    data = (int *) malloc (valnum * sizeof(int));
    if (data == NULL)  
      printf("NO SPACE AVAILABLE.");
  } while (data == NULL); 


  for (i=0; i<valnum; i++) {
    printf("ENTER NUM %d ", i+1);
    scanf("%d", data+i);
  }
 

  for (i=0; i<valnum; i++) 
    sum += *(data+i);
 
  printf("SUM: %ld\n", sum);
  free(data);
}
