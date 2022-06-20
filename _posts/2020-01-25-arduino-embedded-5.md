---
layout: post
title:  Embedded systems programming with atmel328 - 6
tags: arduino atmel processing relay
image: '/images//arduino/keypad.jpg'
date: 2020-01-25 15:01:35 -0700
---



#### About keypads
Keypads are simple input devices that can be used in embedded projects. Most of the time, we can find keyboards being used in access control mechanisms, but they are also used for programming/controlling machines among other cases.  

In this example, we will use a keypad to let the user input a password and then blink a led if the password is correct.

#### The sketch
Here is the sketch for this small lesson. We need to connect each of the in pins on the keyboard to a digital pin on the arduino board. No resistance is needed. In this example I've also added a simple led to be turned on when they correct password is entered.
![keypad1](https://artikblue.github.io/assets/images/arduino/keypadscheme.jpg)


#### But how does it work?
The workflow of a keypad like this one is super simple. Each key of the keypad represents an "open circuit" so when you press on that button, the circuit is closed and the arduino board receives a "HIGH" on a certain pin, so it knows that a key has been pressed!

![keypad2](https://artikblue.github.io/assets/images/arduino/keypad.png)


#### The code
In this case, the code is a bit more complex than what we are used to. In general terms, it uses the Keypad.h library that you can install from the library manager. Then it defines the KEYPAD format with its cells and rows and a pin for the led. The KEYPAD is mapped in the keys array of arrays. A password is defined and then on the main loop, the program will read char by char and when the size of the password is reached it will check whether the password matches the pre-defined one or not.
~~~
#include <Keypad.h>
// byte variable equals 8 bits (half size of an int variable)
// const variables cannot be modified
const byte ROWS = 4;
const byte COLS = 4;
const int LED = 13;
//the actual matrix of our keypad (as it is a MATRICIAL keypad)
// array of arrays of fixed size s
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
// arrays of fixed size
byte pinRow[ROWS] = {9,8,7,6};
byte pinCol[COLS] = {5,4,3,2};

Keypad kp = Keypad(makeKeymap(keys), pinRow, pinCol, ROWS,COLS);

char MKEY[7] = "123456";
char UKEY[7];
byte index = 0;
// variable used for a character ('a','b'....) needed for the Keypad object
char KEY;
void setup() {
  pinMode(LED, OUTPUT);
  Serial.begin(9600);
  
}
void loop() {
   KEY = kp.getKey();
   if(KEY){
    UKEY[index] = KEY;
    index = index + 1;
   }
  if(index >5){
    if(!strcmp(UKEY, MKEY)){
       Serial.println("KEY CORRECT");
       digitalWrite(LED, HIGH);
       delay(500);
       digitalWrite(LED, LOW);
    }
    index = 0;
  }
}
~~~
The keypad object defined inside the kp variable is the key point here, we can use it because we have defined the Keyboard.h library to be used. So in the main loop, the program will wait for a key to be pressed (if(KEY)) then after the key is pressed it will store the key value and move on increasing the index value. When the program reads 6 characters, so the index is 6 it will check the user input with the pre defined key (password). If those char arrays match a led will blink!
  
Key concepts of this program:
1. Keypad.h must be installed and it will then be used.
2. Keypad.h handles a lot of heavy work for us.
3. We can define char arrays in arduino by declaring its size or initializing them with values.
4. We can declare arrays of arrays in arduino, easily.