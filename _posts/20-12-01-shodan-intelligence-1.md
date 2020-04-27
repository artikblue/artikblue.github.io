---
layout: post
title:  "Generating contextual geographic intelligence with shodan"
tags: [shodan, python, analysis]
featured_image_thumbnail: assets/images/shodan.png
featured_image: assets/images/shodan.png
featured: true
hidden: true
---

### About shodan
[Shodan.io](https://shodan.io) is the world known search engine that is continously indexing ipv4/ipv6 hosts connected to the internet and lets you search them by using a wide range of filters such as: network, country, ip or port. 
<!--more-->  

How shodan works internally is still a "mystery" but we can guess that shodan has a certain number of systems that are scanning and re scanning the (whole) internet 24/7 and indexing the results. I guess that shodan identifies features such as location or organisation by gathering and studying information related to ISP companies and IP network ranges. This hypothesis seems reasonable as tools such as [zmap](https://zmap.io/) let you scan the *whole* internet in a matter of minutes.

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

| Description    | Query                                                       |
|----------------|-------------------------------------------------------------|
| after          | Only show results after the given date (dd/mm/yyyy) string  |
| before         | Only show results before the given date (dd/mm/yyyy) string |
| city           | Name of the city string                                     |
| country        | 2-letter country code string                                |
| geo            | lat,lon, kms arround                                        |
| net            | Network range in CIDR notation (ex. 199.4.1.0/24) string    |
| org            | Organization assigned the netblock string                   |
| port           | Port number for the service integer                         |
| vuln           | CVE ID for a vulnerability string                           |
| http.title     | Title for the web banners website                           |
| http.status    | Response status code                                        |
| has_screenshot | True/ False boolean                                         |                                                       

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
import shodan

api_key = "XXX"

api = shodan.Shodan(api_key)
api.info()

results = api.search('country:US apache')
print("Results found: {}" . format(results['total']))
for result in results['matches']:
    print('IP: {}' . format(result['ip_str']))
    print(result['data'])
    print('')
~~~

~~~
artik@blue:~$ python3 sample.py 
Results found: 8740074
IP: 146.71.77.80
HTTP/1.1 200 OK
Date: Sun, 12 Jan 2020 16:59:05 GMT
Server: Apache/2.4.41 (cPanel) OpenSSL/1.0.2t mod_bwlimited/1.4
Transfer-Encoding: chunked
Content-Type: text/html



IP: 184.168.244.3
HTTP/1.1 200 OK
Date: Sun, 12 Jan 2020 16:59:05 GMT
Server: Apache
Last-Modified: Fri, 26 Apr 2013 00:35:46 GMT
Accept-Ranges: bytes
Content-Length: 76
Vary: Accept-Encoding
Content-Type: text/html
~~~

As we see here, we retrieve 8740074 results with this query! By default, the "matches" object is a list that contains the first 100 results, if we want to move to the next page we have to specify page=2 (and so on) in our query: api.search('country:US apache', page = 2). So retrieving information from each page will consume one of our search querries and as you our 100 credits are far from enough for retrieving those 8740074 values. Working on those premises, it is important to say that we need to dimension our queries very well.

### Intelligence gathering and analysis

#### Dimensioning and optimizing our queries

Dimensioning our queries well is not an easy thing and sometimes will be impossible (we'll lose information). There are cases though where a simple query will return less few and interesting analysis (remember, when it comes to analysis, the abscence of a value/result offers information as well).
  
For example, let us look at this query related to gas pumps:

![gas](https://artikblue.github.io/assets/images/shodan/gas_spots.JPG)

We can see that the query returns few values and we can get them all. And it even returns very nice information such as the gas tank levels of each pump.

![gaslevels](https://artikblue.github.io/assets/images/shodan/gaslevels.JPG)

Those values could help us in the analysis or in the monitorization of a specific technology, it could also help an attacker in conducting sabotage operations against a specific region. But in situations such as that one has to think in perspective, on this case, there are thousands of different gas pumps out there and probably we are receiving a ridiculous part of them on that query.

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

We can also download the shodan data in a json format and save it to a mongodb for further analysis. R may be a good way to do data analysis on that. Here I show some very basic descriptive analysis as an example:

~~~
> library(mongolite)
> library(plyr)
> library(dplyr)
> library(ggplot2)
> con <- mongo("net", url = "mongodb://127.0.0.1:27017/nk")
> mydata <- con$find('{"location.country_code": "KP"}')
> unique(mydata["asn"])
       asn
1 AS131279
> unique(mydata["org"])
            org
1 Ryugyong-dong
> unique(mydata["isp"])
            isp
1 Ryugyong-dong
> unique(mydata["port"])
   port
1   443
2  8080
3    80
6    53
9    25
12   21
19   22
23  587
29   23
> port <- mydata %>% group_by(port)
> count(port)
# A tibble: 9 x 2
# Groups:   port [9]
  port      n
  <chr> <int>
1 21        2
2 22        1
3 23        1
4 25        4
5 443       2
6 53        3
7 587       1
8 80        2
9 8080     18
> unique(mydata["product"])
                     product
1        Microsoft IIS httpd
2                       <NA>
9                   Sendmail
21              Apache httpd
22             Postfix smtpd
24 Cisco PIX sanitized smtpd
29      Cisco router telnetd
> product <- mydata %>% group_by(product)
> count(product)
# A tibble: 7 x 2
# Groups:   product [7]
  product                       n
  <chr>                     <int>
1 Apache httpd                  2
2 Cisco PIX sanitized smtpd     1
3 Cisco router telnetd          1
4 Microsoft IIS httpd           2
5 Postfix smtpd                 2
6 Sendmail                      2
7 NA                           24
> unique(mydata["devicetype"])
   devicetype
1        <NA>
24   firewall
29     router
> devicetype <- mydata %>% group_by(devicetype)
> count(devicetype)
# A tibble: 3 x 2
# Groups:   devicetype [3]
  devicetype     n
  <chr>      <int>
1 firewall       1
2 router         1
3 NA            32
> 
~~~
As we can see from here and taking the data we got from the map into account as well. We can theorize that most of the DPRK net infrastructure is private and hidden inside the country, though some external communications are needed for the country. According to the map, those hosts are located within the *Potonggang-guyok* area, an area that hosts one of the DPRKs strategic headquarters. Most of the devices, almost each of them are network equipment such as mail and web servers. Some routers/firewall appear as well, there is a chance that some of those are routing some internal traffic outside the country.
#### Iran nuclear reactors in the spotlight
Another interesting case of studio is using shodan to detect device activity near critical infrastructures such as power plants. Iran has been very relevant in the international geo political scenario, so let's try to peek there.  


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
import shodan
import pymongo
api_key = "xXxXx"

api = shodan.Shodan(api_key)
api.info()

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["iran"]


nuclear_reactors = {
    'lavizan':'geo:35.773056, 51.497778, 80',
    'natanz':'geo:33.723453, 51.727097, 80',
    'parchin':'geo:35.52, 51.77, 80',
    'saghand':'geo:32.313, 55.53, 80',
    'tehran':'geo:35.738333, 51.388056, 80'
}

for n in nuclear_reactors.keys():
    print(nuclear_reactors[n])
    col = mydb[n]
    results = api.search(nuclear_reactors[n])
    print("Results found: {}" . format(results['total']))

    for r in results["matches"]:
        x = col.insert_one(r)
        print(x)
~~~
And then we can run some analyses on the data. This analyses showed relevant device activity near lavizan and parchin facilities. Parchin is specially interesting because is one of the main facilities related to Irans military nuclear program.
#### Maping the ucranian industrial sector
Finally this last use-case scenario involves the power of shodan as an auxiliary tool to map the industrialization of a country. By shodan we can look for ICS devices (industrial control systems). ICSs are very rarely found in networks/facilities that are not related to industries (or are industries themselves). So, searching for those may reveal the location of large industrial areas. Industrial systems often relate to critical infrastructures. In this example I'm detecting industrial infrastructures in Ucrania. I've chose Ucrania because it suffered from blackouts related to cyberattacks recently (or thats what some people say).

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

I will update this post with relevant information as soon as I make more time. That said, I want to state that I do not have anything against the countries studied on this post, sure they are full of charming people as any other nation in the world.  

Be good!