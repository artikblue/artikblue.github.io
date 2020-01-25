---
layout: post
title:  "Embedded systems programming with atmel328 - 5"
author: artikblue
categories: [ embedded, course ]
tags: [arduino, atmel, processing, relay]
image: assets/images/arduino/relayheader.jpg
description: "Course on programming embedded systems with arduino-like boards, part 4. Working with relays"
featured: true
---

#### What is a Relay?


#### The Sketch


![relay1](https://artikblue.github.io/assets/images/arduino/relay1.JPG)


#### But how does it really work?

If you look at the hl54s relay you'll see one or more blue boxes, those are the relays and before each one, you'll see a tiny black box, that box contains a circuit like this, that receives input from the arduino (or whatever) board and forms a circuit with the inductor that triggers the relay mechanically.

![relay1](https://artikblue.github.io/assets/images/arduino/relay_schematic_component.JPG)

And why we do it this way? Basically a relay will be dealing with really high voltages, so eventhough if properly designed and operated, this circuit will never let high voltage directly interact with the arduino circuit, we don't want any kind physical contact between those voltages and the actual board and that is why we use a light emitting diode to trigger the (photo sensible) transistor, so they are not physically connected so if something fails we'll have less risk.

#### Sample code


~~~
int RELAY = 2;

void setup() {
  // analog inputs do not requiere initialization
  pinMode(RELAY, OUTPUT);
}

void loop() {
  //relays get activated with a LOW level
  digitalWrite(RELAY, LOW); 
  delay(5000);
  digitalWrite(RELAY, HIGH);
  delay(5000);
}
~~~