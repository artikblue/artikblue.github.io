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
[Shodan.io](https://shodan.io) is the world known search engine that is continously indexing ipv4/ipv6 hosts connected to the internet and lets you search them by using a wide range of filters such as: network, country, ip or port. How shodan works internally is still a "mystery" but we can guess that shodan has a certain number of systems that are scanning and re scanning the (whole) internet 24/7 and indexing the results. I guess that shodan identifies features such as location or organisation by gathering and studying information related to ISP companies and IP network ranges. This hypothesis seems reasonable as tools such as [zmap](https://zmap.io/) let you scan the *whole* internet in a matter of minutes.
  
So with shodan we can search for devices that are connected to the internet. The services is focused to the device, so instead of google, in here we are able to look for web apps, ports, custom apps or whatever, not just web pages. This services can be used for multiple purposes, for example it can be used by attackers or pentesters to audit a specific network looking for some specific application or to mass attack a specific vulnerability, it can also be used by social scientists or industrial researchers to know more about the impact of a certain technology in the world. On this post I'm going to show you how shodan can be useful for analysts for detecting infrastructures on different countries.
  
Some interesting things that you have to take into account related to shodan are:
1. You see N hosts up after a search on shodan, there can be more hosts out there than the ones that appear in shodan.
2. By using shodan, those hosts won't detect that YOU are scanning them, but shodan will know what you are doing.
3. Shodan offers different kinds of access to the platform, if you want to do serious stuff get you'll have to pay a lot.
  
For this intro post I'm using a simple account with a basic developer license I got by paying 10$ due to an offer. It let's me perform 100 searches a month.
#### Queries and filters
You can just hit the shodan search bar and type something like "apache" and yes, that will probably show you hosts containing the apache server service, but it may also show you hosts running nginx with apps containing the word apache and there are ways to be more accurate. Shodan works well with filters, a filter like port:80 will show you hosts with port 80 open. Filters can be concatenated so port:80 and country:US will show you hosts in the US with port 80 open. You can also use parentheses () and the OR keyword to perform advanced searches.
##### Filters
Here you can find some of the filters that I find more useful:
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
Now that you know some filters, the possibilities are big. Shodan is a tool that is specially useful if you *already know what you are doing* so for example if you are an ICS expert and want to look for a specific vulnerabilitty it will work miracles for you, as you'll probably know many *service banners* related to the ICS systems that you are looking for. 
  
You can find plenty of interesting search queries out there, people use shodan to find stuff that goes from webcaams, outdated software or even gas stations or drones. Some juicy search queries can be found here:

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

When it comes to search results shodan comes out with nice stuff. Shodan will map the results for you, so you'll see what countries and organizations your results belong to.

![webcams](https://artikblue.github.io/assets/images/shodan/webcams.JPG)

You can easily do a first analysis in the webapp itself.

![webcams](https://artikblue.github.io/assets/images/shodan/webcamscountries.JPG)

And if you click in the hosts, you'll retrieve more information. You can also open the host in the browser (if it contains a web app):

![webcams](https://artikblue.github.io/assets/images/shodan/webcamexaple.JPG)

The results can be pretty funny. For example, in this case, I looked for the webcamxp software and a bunch of results came out. Well it turns out that the [webcamxp](https://www.exploit-db.com/exploits/18510) has a software vulnerability and the same thing happens with a lot of services that you can find in hosts that are acually indexed in shodan...
#### The shodan api

The web is OK but if we want to do some more serious stuff we would like to autmate our queries and maybe we would like to auto insert our results to a database/dataset for further analysis. That can be done by using the shodan python api. It can be installed by
~~~
pip install shodan
~~~
And a hello world query using the api would look like:
~~~
~~~


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

We can automate the search using the api and index the results in mongo:
~~~
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