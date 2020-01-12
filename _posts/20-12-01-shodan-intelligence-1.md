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

#### The shodan api

### Intelligence gathering and analysis

### Dimensioning and optimizing our queries

### A peek inside the DPRK network range

### Iran nuclear reactors in the spotlight

### Maping the ucranian industrial sector

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