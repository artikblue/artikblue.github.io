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
Servo motors are small dc engines that transmit their power to a series of gears to maximize the amount of weight they can move (at the cost of their speed). Thus, by that concept servos are very powerful and are used in many many diy projects such as robots and all kinds of automatisms. You can find many different kinds of servos, some  small and not so powerful to big servos capable of moving heavy weights and with a high demand of energy. So, this components, by the effort they have to do, tend to have stronger power needs. In this example we are dealing with the KY66 9g servo that does not have heavy power requirements, eventhough I recommend that you get yourself an external power transformer for your arduino, so that you can power up your arduino without the usb connection and thus avoid potential harms or problems.  
This servo we are using here is capable of moving 9g and requieres a voltage close to 5 dc. Its red cable goes to 5v dc, brown goes to ground and the orange one goes to a pwm pin. Note that servos like this one have 180 degrees of movement.
Find more information about the servo ["on its datasheet"](http://www.ee.ic.ac.uk/pcheung/teaching/DE1_EE/stores/sg90_datasheet.pdf)
### Prototype
The prototype for this project is quite simple. We will make a servo engine turn to the left or to the right as we move a potentiometer. We already know how to set up a potentiometer and read its value, the servo is simple as well we only need to feed power to it and wire it to a pwm port. 
![servo](https://artikblue.github.io/assets/images/sketches/servo.JPG)
For easily working with the servo, the Serv.h library is very useful. We could work with the servo without any library thoug it would be much harder and would requiere more code (and harder to understand), in further publications we'll write some pure C code to do it manually, by now, the library is will work fine. 
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
In this program we define the second pin to be used with the servo and pin 0 to be used for the potentiometer, the analog pin (as input) for the potentiometer does not need to be defined. Then we define a minimum pulse and a maximum pulse as the servo is controlled by pulse with modulation (pwm), so we can understand that this way: if we send a pulse of 1200 the servo will move to a position (angle) if we send a pulse of (1500) then it will move 30 degrees from that position. How do we know that the ranges go from 1000 to 2000? Checking the datasheet provided by the manufactured and or by trial and error. So with servo.attach() we specifiy the pin for the servo and then the pulse range.  

On the main loop we start by reading the value from the potentiometer and then we map that value to 0-180 as the servo can move in 180 degrees. You may think about why we write an angle to the servo instead of a pulse, well as we attached (kind of initialized) the servo with that range the mapping will be done automatically for us, so we can work with angles (easier).

