---
layout: post
title:  "Embedded systems programming with atmel328 - 1"
author: artikblue
categories: [ embedded, course ]
tags: [arduino, atmel, processing]
image: assets/images/arduino/desktop2.png
description: "Course on programming embedded systems with arduino-like boards, part 1."
featured: true
---

## About this course



## Setting up the environment

### Arduino IDE

![ide](https://support.content.office.net/es-es/media/e8c360e1-2b32-45db-b9d7-d43abc86af2f.png)
*support.content.office.net*


~~~
sudo apt-get install arduino
~~~


### Interacting with arduino in VirtualBox VM

![comport](https://artikblue.github.io/assets/images/arduino/comport.png)
*http://joequery.me/*

![virtualbox](https://artikblue.github.io/assets/images/arduino/virtualport.png)
*http://joequery.me/*

### Manually uploading code to arduino

~~~
sudo apt-get install picocom ino
~~~

#### Using Ino
~~~
mkdir testproject
cd testproject

ino init

cd ~/arduino/testproject

ino build
ino upload -p /dev/ttyS0
~~~

#### Using AVRDude


~~~
artik@blue:/tmp/build6422050015977722322.tmp$ file sketch_jan08a.cpp.elf
sketch_jan08a.cpp.elf: ELF 32-bit LSB executable, Atmel AVR 8-bit, version 1 (SYSV), statically linked, with debug_info, not stripped
artik@blue:/tmp/build6422050015977722322.tmp$ 
~~~

~~~
artik@blue:/tmp/build6422050015977722322.tmp$ ls -lah | grep sketch
-rw-rw-r--  1 red  red   378 ene 11 18:30 sketch_jan08a.cpp
-rw-rw-r--  1 red  red   753 ene 11 18:30 sketch_jan08a.cpp.d
-rw-rw-r--  1 red  red    13 ene 11 18:30 sketch_jan08a.cpp.eep
-rwxrwxr-x  1 red  red   37K ene 11 18:30 sketch_jan08a.cpp.elf
-rw-rw-r--  1 red  red  3,2K ene 11 18:30 sketch_jan08a.cpp.hex
-rw-rw-r--  1 red  red   17K ene 11 18:30 sketch_jan08a.cpp.o
artik@blue:/tmp/build6422050015977722322.tmp$ 
~~~


~~~
avrdude -c usbtiny -p m328p -U flash:w:firmware.hex
~~~

## Prototyping

### Prototyping with frietzing

### Protoboard

## Our first project

### Powerring a led

![basicled](https://artikblue.github.io/assets/images/sketches/ledboton.JPG)



~~~
int LED = 10;
int BUTTON = 4;
int val;

void setup() {
  pinMode(LED, OUTPUT);
  pinMode(BUTTON, INPUT);
}

void loop() {
   val = digitalRead(BUTTON);
   if(val==HIGH){
      digitalWrite(LED,HIGH);
   }
   else{
      digitalWrite(LED,LOW);
   }
}
~~~


### Led fading through pwm

![pwmled](https://artikblue.github.io/assets/images/sketches/pwmledpote.JPG)

~~~
int LED = 3;
int POT = 0; //potentiometer
int LEDSHINE;

void setup() {
  // analog inputs do not requiere initialization
  pinMode(LED, OUTPUT);
}

void loop() {
  //analog read reads from 0 a 1023 in this case
   LEDSHINE = analogRead(POT)/4; //to adjust it to 255 scale
   analogWrite(LED, LEDSHINE);
}
~~~
