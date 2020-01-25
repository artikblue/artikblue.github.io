---
layout: post
title:  "Embedded systems programming with atmel328 - 5"
author: artikblue
categories: [ embedded, course ]
tags: [arduino, atmel, processing, relay]
image: assets/images/arduino/relayheader.jpg
description: "Course on programming embedded systems with arduino-like boards, part 4. Working with relays"
---

#### What is a Relay?
A relay is an electrically operated switch. It consists of a set of input terminals for a single or multiple control signals, and a set of operating contact terminals. The switch may have any number of contacts in multiple contact forms, such as make contacts, break contacts, or combinations thereof.
#### The Sketch

The sketch for this design is pretty simple, no protoboard needed. Basically, the relay module, needs to be connected to GND and 5v VCC and then to a digital pin that will control it for switching it on/off. After connecting the relay to the arduino board you will see how a small led turns on on the relay board, that means the relay is working. Then at the other side of the relay we have connection points, NC, C and NO. NC means closed, NO means open and C is the common point of contact. We will connect the POWER cable of the device we want to control to NO. Then we will go for the external power supply, which can be a battery, power station or even a connection to your home electricity network. We will connect the GROUND connection to the GROUND of our external power supply and the V cable of our power supply will go straight to the C connection point on the relay, as you can see here:
![relay1](https://artikblue.github.io/assets/images/arduino/relay1.JPG)
Then with that, the behaviour of the relay is simple, when the relay control pin receives a LOW value, the relay triggers a mechanical device that closes the circuit between the external device and the external power supply, if it receives a high it opens the circuit.

#### But how does it really work?

If you look at the hl54s relay you'll see one or more blue boxes, those are the relays and before each one, you'll see a tiny black box, that box contains a circuit like this, that receives input from the arduino (or whatever) board and forms a circuit with the inductor that triggers the relay mechanically.

![relay1](https://artikblue.github.io/assets/images/arduino/relay_schematic_component.JPG)

And why we do it this way? Basically a relay will be dealing with really high voltages, so eventhough if properly designed and operated, this circuit will never let high voltage directly interact with the arduino circuit, we don't want any kind physical contact between those voltages and the actual board and that is why we use a light emitting diode to trigger the (photo sensible) transistor, so they are not physically connected so if something fails we'll have less risk.

#### Sample code
One of the most complicated things related to relays is the correct dimensioning of the power we need for our external device and stuff like finding batteries or getting/building some adapter for our external power supplies, the code is mega simple. In here we just have to note that relays get activate with LOW values:
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