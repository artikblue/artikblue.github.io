---
layout: post
title:  "Embedded systems programming with atmel328 - 3 (microservos)"
author: artikblue
categories: [ embedded, course ]
tags: [arduino, atmel, processing]
image: assets/images/arduino/pservo.jpg
description: "Working with (micro) servo motors in arduino."
---

### About servo-motors

### Prototype

![ultrasound](https://artikblue.github.io/assets/images/sketches/servo.JPG)


### Code

~~~
#include <Servo.h>

Servo servo1;

//arduino uno pin 2 pwm
int PINSERVO = 2;
//pulse range from  the servo
int PULSEMIN = 1000;
int PULSEMAX = 2000;

int VALPOT;
int ANGLE;
int POT = 0;

void setup() {
  //analogical inputs do not require initialization!!!
  //we specify the pin of the servo, then the pulse range. We need to do some trial and error to know the real pulse range
  //though we can start with 1000 to 2000 and start moving from there
  servo1.attach(PINSERVO, PULSEMIN, PULSEMAX);
}

void loop() {
  //we read from the potentiometer. We will read a val from 0 to 1023
  VALPOT = analogRead(POT);
  //the servo will has a 180 degree movement capability so we need to do a maping
  ANGLE = map(VALPOT, 0, 1023, 0, 180);
  //we just write the result to the servo
  servo1.write(ANGLE);
  //the servo should move as we move the potentiometer... magic!
  delay(20);
}
~~~


