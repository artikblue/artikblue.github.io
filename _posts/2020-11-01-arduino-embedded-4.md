---
layout: post
title:  "Embedded systems programming with atmel328 - 4 (temperature&humidity)"
author: artikblue
categories: [ embedded, course ]
tags: [arduino, atmel, processing]
image: assets/images/arduino/pdht.jpg
description: "Working with the DHT22 temperature and humidity sensor."
---

### About servo-motors

### Prototype

![ultrasound](https://artikblue.github.io/assets/images/sketches/dht.JPG)


### Code

~~~
#include <DHT.h>    // install: "DHT sensor library by Adafruit"
#include <DHT_U.h> // install "Adafruit Unified Sensor by Adafruit"

int SENSOR = 2;     // digital 2 pin data.
// DHT22 is the one used here. Reads from -40 to 125 celsius error is -+0.5 degrees
// humidity 0% to 100% +-2.5% of error
//3 to 5.5 v
int TEMP;
int HUMIDIT;

DHT dht(SENSOR, DHT22);   // we create the object, we are monitoring a DHT22 (other option is DHT11)
void setup(){
  Serial.begin(9600);   // serial initialization
  dht.begin();      // sensor initialization
}

void loop(){
  TEMP = dht.readTemperature();  // get current temp
  HUMIDIT = dht.readHumidity();   // get current humidity
  Serial.print("Temp: ");  // writing
  Serial.print(TEMP);
  Serial.print(" Hum: ");
  Serial.println(HUMIDIT);
  delay(500);
}
~~~


