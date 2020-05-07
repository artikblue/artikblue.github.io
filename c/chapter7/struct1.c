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
