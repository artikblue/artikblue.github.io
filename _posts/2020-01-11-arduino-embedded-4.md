---
layout: post
title:  Embedded systems programming with atmel328 - 4 (temperature&humidity)
tags: arduino atmel processing
image: '/images//arduino/pdht.jpg'
date: 2020-01-11 15:01:35 -0700
---

### About dht22
The DHT22 sensor is the next version of the DHT11 sensor and is capable to read temperature and humidity values ranging from 0 to 80 celsius degrees and from 0 to 100% humidity level. It is one of the most well known sensors used in diy projects in the arduino lands.  

In this case the DHT22 that we are using has four pins:
1. VCC (3-5V)
2. DATA: receives the temp and humidity readings
3. NC (not used here)
4. GND
### Prototype
On this example I used a 4.7Kohm resistor between DATA and VCC as a pull up resistor. The pull up resistor ensures a valid logic level when the pins are switching from input to output. So this resistor helps us in making our readings stable.
![ultrasound](https://artikblue.github.io/assets/images/sketches/dht.JPG)


### Code
Working with sensors such as the DHT "in raw" can be a bit hard as for example in this one we are receiving humidity and temperature at the same pin by the same wire and you can also guess that those values won't come in pure decimal. In this case libraries such as the DHT/DHTU will help a lot. We'll have to install those manually by going into "Program" and "library management" and then we'll have to search for "DHT sensor library" and "adafruit unified sensor", those will work for us and with them reading temperature and humidity will be easy.
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
On this case the code is mega simple. As we can see the library does everything for us. Working with external libraries is a common/natural part in our path as embedded developers. A final thing that I want you to note here is that eventhough there are a lot of similarities *every sensor lives on his on world* so you always have to check the data sheet written by the manufacturer to know how to work with the component and yes, libraries do help a lot.

