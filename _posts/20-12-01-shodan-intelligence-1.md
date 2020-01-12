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

| after          | Only show results after the given date (dd/mm/yyyy) string                                                                                                                                                                 |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
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

#### The shodan api

### Intelligence gathering and analysis

#### Dimensioning and optimizing our queries

#### A peek inside the DPRK network range



After some research I've found the following query in many publications related to the North Korean internet.
~~~
net:175.45.176.0/22,210.52.109.0/24,77.94.35.0/24
~~~
Eventhough after retrieving the results I find a lot of hosts related to Latvia and some actually related to DPRK. After some more research one can find ["the following"](https://lite.ip2location.com/korea-(democratic-peoples-republic-of)-ip-address-ranges) network ranges related to DPRK. So one can see that *175.45.176.0/22* and *202.72.96.4/29* would perform a more accurate and effective search.

~~~
net:175.45.176.0/22,202.72.96.4/29
~~~


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