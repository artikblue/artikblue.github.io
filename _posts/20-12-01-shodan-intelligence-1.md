---
layout: post
title:  "Generating contextual geographic intelligence with shodan"
author: artikblue
categories: [ data, intelligence ]
tags: [shodan, python, analysis]
image: assets/images/shodan.png
description: "Using shodan and its filters to retrieve sensitive data from specific regions to generate intelligence."
featured: true
---

### About shodan

#### Queries and filters

##### Filters

| Description    | Query                                                                                                                                                                                                                      |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| after          | Only show results after the given date (dd/mm/yyyy) string                                                                                                                                                                 |
| before         | Only show results before the given date (dd/mm/yyyy) string                                                                                                                                                                |
| city           | Name of the city string                                                                                                                                                                                                    |
| country        | 2-letter country code string                                                                                                                                                                                               |
| geo            | Accepts between 2 and 4 parameters. If 2 parameters: latitude,longitude. If 3 parameters: latitude,longitude,range. If 4 parameters: top left latitude, top left longitude, bottom right latitude, bottom right longitude. |
| net            | Network range in CIDR notation (ex. 199.4.1.0/24) string                                                                                                                                                                   |
| org            | Organization assigned the netblock string                                                                                                                                                                                  |
| port           | Port number for the service integer                                                                                                                                                                                        |
| vuln           | CVE ID for a vulnerability string                                                                                                                                                                                          |
| http.title     | Title for the web banners website                                                                                                                                                                                          |
| http.status    | Response status code                                                                                                                                                                                                       |
| has_screenshot | True/ False boolean                                                                                                                                                                                                        |

##### Interesting queries

| Description                                    | Query                                                     |
|------------------------------------------------|-----------------------------------------------------------|
| Gas Station Pump Controllers                   | "in-tank inventory" port:10001                            |
| Traffic Light Controllers / Red Light Cameras  | mikrotik streetlight                                      |
| Telcos Running Cisco Lawful Intercept Wiretaps | "Cisco IOS" "ADVIPSERVICESK9_LI-M"                        |
| Submarine Mission Control Dashboards           | title:"Slocum Fleet Mission Control"                      |
| Railroad Management                            | "log off" "select the appropriate"                        |
| Unprotected VNC                                | "authentication disabled" "RFB 003.008"                   |
| MongoDBs                                       | "MongoDB Server Information" port:27017 -authentication   |
| FTP Servers with Anonymous Login               | "220" "230 Login successful." port:21                     |
| webcamXP/webcam7                               | ("webcam 7" OR "webcamXP") http.component:"mootools" -401 |
| Etherium Miners                                | "ETH - Total speed"                                       |
| Job offers (lol)                               | "X-Recruiting:"                                           |
| Chromecasts / Smart TVs                        | "Chromecast:" port:8008                                   |


![webcams](https://artikblue.github.io/assets/images/shodan/webcams.JPG)

![webcams](https://artikblue.github.io/assets/images/shodan/webcamscountries.JPG)

![webcams](https://artikblue.github.io/assets/images/shodan/webcamexaple.JPG)

#### The shodan api

### Intelligence gathering and analysis

#### Dimensioning and optimizing our queries


![gas](https://artikblue.github.io/assets/images/shodan/gas_spots.JPG)

![gaslevels](https://artikblue.github.io/assets/images/shodan/gaslevels.JPG)

#### A peek inside the DPRK network range



After some research I've found the following query in many publications related to the North Korean internet.
~~~
net:175.45.176.0/22,210.52.109.0/24,77.94.35.0/24
~~~
Eventhough after retrieving the results I find a lot of hosts related to Latvia and some actually related to DPRK. After some more research one can find ["the following"](https://lite.ip2location.com/korea-(democratic-peoples-republic-of)-ip-address-ranges) network ranges related to DPRK. So one can see that *175.45.176.0/22* and *202.72.96.4/29* would perform a more accurate and effective search.

~~~
net:175.45.176.0/22,202.72.96.4/29
~~~

![nk1](https://artikblue.github.io/assets/images/shodan/nk1.JPG)

#### Iran nuclear reactors in the spotlight

In this case, the *geo* filter comes very handy. As facilities such as nuclear reactors are not very often located in the middle of a city, in scenarios such as these we'll have to do our side research, identify reasonable coordinates/geo areas and aim there. I've built a python dictionary with the following:
~~~
nuclear_reactors = {
    'lavizan':'geo:35.773056, 51.497778, 80',
    'natanz':'geo:33.723453, 51.727097, 80',
    'parchin':'geo:35.52, 51.77, 80',
    'saghand':'geo:32.313, 55.53, 80',
    'tehran':'geo:35.738333, 51.388056, 80'
}
~~~


#### Maping the ucranian industrial sector

The queries I've used to map the ICS devices were these:

| System               | Query                                       |
|----------------------|---------------------------------------------|
| MODBUS ICS           | port:502                                    |
| SIEMENS S7           | port:102                                    |
| DNP3                 | port:20000 source address                   |
| TRIDIUM FOX PROTOCOL | port:1911,4911 product:Niagara              |
| BACNET               | port:47808                                  |
| Ethernet/IP          | port:44818                                  |
| GR-SRTP              | port:18245,18246 product:"general electric" |
| HART-IP              | port:5094 hart-ip                           |
| PCWORX PLC           | port:1962 PLC                               |
| MELSEC-Q             | port:5006,5007 product:mitsubishi           |
| OMRON                | port:9600 response code                     |
| REDLION              | port:789 product:"Red Lion Controls"        |
| CODESYS              | port:2455 operating system                  |
| IEC 60870 SCADA      | port:2404 asdu address                      |
| ProConOS             | port:20547 PLC                              |

And one mega query would look like this:

~~~
country:IR (port:502 OR port:102 OR port:20000 source address OR port:1911,4911 product:Niagara OR port:47808 OR port:44818 OR port:18245,18246 product:"general electric" OR port:5094 hart-ip OR  port:1962 PLC OR port:5006,5007 product:mitsubishi OR port:9600 response code  OR port:789 product:"Red Lion Controls" OR port:2455 operating system OR port:2404 asdu address OR port:20547 PLC) 
~~~

After an initial analysis of the data we can realise that "moodbus" is the protocol were most of the systems belong to. So taking that into account, we can infere a couple of things:

1. In areas/systems were "modbus" is present we'll probably find other ICS systems of different kind.
2. Orgs containing "modbus" systems will probably industrial organizations.

Said that, we can conclude that "modbus" may be a good indicator. So we can use the shodan map with that:

![modbus](https://artikblue.github.io/assets/images/shodan/ua_ics.JPG)

As we can see traditional industrial Ucranian regions such as Kyiv or the Donbass stand out from the rest thus we can see that the map is not far from reality and can be considered. Eventhoug this is a very simplistic example, more comprobations should be made as it is possible, for example, to have more industrialized regions that use a different technology or a technology that is heavily secured (or not even connected to the internet). What is true is that the regions shown in the map contain industrial systems and thus contain industries.