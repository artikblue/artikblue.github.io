---
layout: post
title:	"Hello world post"
date:	2020-01-05 12:00:00
categories:
    - blog
tags:
    - datascience
    - r
---
this is a test :)

## Data analysis

### Basic data analysis
~~~
> con <- mongo("realestate_renting", url = "mongodb://127.0.0.1:27017/habitaclia")
> con$count()
[1] 6114
~~~
We can see that our dataset is composed by a total of 6114 flat renting offers.

~~~
> mydata <- con$find('{}')
> print("Studied areas")
[1] "Studied areas"
> unique(mydata["subzone"])
                            subzone
1    Cuenca del Alberche-Guadarrama
14           Cuenca del Tajo-Tajuña
31                           Madrid
366                        Zona Sur
1743                  Zona Noroeste
4243           Corredor del Henares
4797                     Zona Norte
> print("Studied villages")
[1] "Studied villages"
> unique(mydata["village"])
                                               village
1                                      Zona El Pijorro
2                                   Zona Casco Antiguo
3                                     Sevilla la Nueva
4                                              Brunete
5                                           Álamo (El)
6                                           Chapinería
7                                 Zona El Pinar-Dehesa
9                               Cadalso de los Vidrios
10                                 Pelayos de la Presa
[...]
5213                                  Zona Los Arroyos
5302                                        Valdelagua
5397                                            Cobeña
5437                                            Madrid
5671                  Zona El Cañaveral-Los Berrocales
5989  
~~~

~~~
> print("general means")
[1] "general means"
> # GENERAL MEANS (relevant data)
> sapply(mydata["price"],mean)
   price 
2117.328
> sapply(mydata["price"],median)
price 
 1300 
> sapply(mydata["surface"],mean)
 surface 
128.5034 
~~~

![priceboxplot]({{ site.baseurl }}images/blog/madrid_renting/priceboxplot.png)

~~~

~~~



~~~

~~~



~~~

~~~


~~~

~~~