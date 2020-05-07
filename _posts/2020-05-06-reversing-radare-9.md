---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 9 (pointers and dynamic memory)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_10.png
featured_image: assets/images/radare2/radare2_10.png
---


```C
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
```


```C

```

```C
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
```
