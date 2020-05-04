---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 7 (struct arrays, r2pm and patching)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_8.png
featured_image: assets/images/radare2/radare2_8.png
---
****** draft


So today we are going to work with a more complete example, the goal is to correctly understand how the program works interally and explore some nice topics.
```
#include <stdio.h>

const int MAX = 20;

struct stud
	{
		char fletter;
		int age;
		float mark;
	};

main(){
	func1();
	getchar();
}


void showstudents(struct stud students[], int n){

	printf("Showing students: \n");

	for(int i = 0; i < n; i++){
		printf("Student num %d: ", i);
		printf("First letter = %c ", students[i].fletter);
		printf("Age = %d ", students[i].age);
		printf("Mark = %f \n", students[i].mark);
	}


}


int addstudents(struct stud students[], int i){
	printf("Round: %d \n", i);

	if(i > MAX){
		printf("Students list is FULL\n");
		return -1;
	}
	else{
		printf("First letter?\n");
		scanf(" %c",&students[i].fletter);

		printf("Age?\n");
		scanf(" %i",&students[i].age);

		printf("Mark?\n");
		scanf(" %f",&students[i].mark);

		

		return i+1;
	}

}

func1(){

	struct stud students[MAX];

	int i = 0;
	char q =' ';

	while(q != 'q' && i!=-1){
		printf("Action? (q=Quit, a=Add, s=ShowAll)\n");

		scanf(" %c", &q);
		if(q == 'a'){
			i = addstudents(students,i);

			
			
		}
        
		
	}
}
```

```

*the patch

```
[0x0000138b]> s 0x000014b8
[0x000014b8]> wa inc [ebp-0x2c]


[0x0000118f]> s 0x000011a5

[0x000011a5]> wa call sym.addstudents
Written 5 byte(s) (call sym.addstudents) = wx e8d5000000


[0x000011a5]> s 0x0000119e
[0x0000119e]> wa nop
Written 1 byte(s) (nop) = wx 90

[0x0000118f]> s 0x0000119f
[0x0000119f]> wa nop


[0x0000138b]> s 0x000014b3
[0x000014b3]> wa call sym.showstudents
Written 5 byte(s) (call sym.showstudents) = wx e8d7fcffff
```