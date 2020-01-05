---
layout: post
title:	"Madrid real estate renting market data analysis"
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

![priceboxplot](https://artikblue.github.io/images/blog/madrid_renting/priceboxplot.png)

![surfaceboxplot](https://artikblue.github.io/images/blog/madrid_renting/boxplotsurface)

![roomsboxplot](https://artikblue.github.io/images/blog/madrid_renting/boxplotrooms.png)

![toiletsboxplot](https://artikblue.github.io/images/blog/madrid_renting/boxplottoilets.png)


![pricedensity](https://artikblue.github.io/images/blog/madrid_renting/densityprice.png)

![surfacedensity](https://artikblue.github.io/images/blog/madrid_renting/surfacedensity.png)

![roomsdensity](https://artikblue.github.io/images/blog/madrid_renting/roomsdensity.png)

![toiletsdensity](https://artikblue.github.io/images/blog/madrid_renting/toiletsdensity.png)

~~~
> print("data summaries")
[1] "data summaries"
> # SUMMARIES
> summary(mydata$price)
     Min.   1st Qu.    Median      Mean   3rd Qu.      Max. 
    200.0     936.2    1300.0    2117.3    2000.0 1800000.0 
> summary(mydata$surface)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max. 
    0.0    65.0    92.0   128.5   142.8   992.0 
> summary(mydata$numpics)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max. 
   0.00   11.00   18.00   20.32   28.00  123.00 
> summary(mydata$rooms)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max. 
   1.00    2.00    2.00    2.61    3.00   24.00 
> summary(mydata$toilets)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max. 
  1.000   1.000   2.000   1.997   2.000  26.000 
~~~



~~~
> villages <- mydata %>%
+   group_by(village) %>%
+   summarize(price_mean=mean(price), price_deviation=sd(price), price_var=var(price),
+             price_median=median(price), total_val=length(price),price_max=max(price),
+             price_min=min(price),price_range=max(price)-min(price), rooms_med=mean(rooms), 
+             toilets_med=mean(toilets), npics_med=mean(numpics),
+             surface_max=max(surface), surface_min=min(surface), surface_mean=mean(surface),
+             surface_median=median(surface), surface_sd=sd(surface), surface_varr=var(surface),
+             surface_range=max(surface)-min(surface), price_meter=sum(price)/sum(surface))
> zones <- mydata %>%
+   group_by(subzone) %>%
+   summarize(price_mean=mean(price), price_deviation=sd(price), price_var=var(price),
+             price_median=median(price), total_val=length(price),price_max=max(price),
+             price_min=min(price),price_range=max(price)-min(price), rooms_med=mean(rooms), 
+             toilets_med=mean(toilets), npics_med=mean(numpics),
+             surface_max=max(surface), surface_min=min(surface), surface_mean=mean(surface),
+             surface_median=median(surface), surface_sd=sd(surface), surface_varr=var(surface),
+             surface_range=max(surface)-min(surface), price_meter=sum(price)/sum(surface))
~~~

![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/basicpairs.png)


~~~
> select(zones %>% arrange(-total_vals), zone, total_vals)
# A tibble: 7 x 2
  zone                           total_vals
  <chr>                                  <int>
1 Madrid                                  4455
2 Zona Noroeste                            718
3 Zona Sur                                 341
4 Zona Norte                               309
5 Corredor del Henares                     171
6 Cuenca del Tajo-Tajuña                    84
7 Cuenca del Alberche-Guadarrama            36
> select(zonas %>% arrange(-price_avg), zone, price_avg)
# A tibble: 7 x 2
  zone                           price_avg
  <chr>                                 <dbl>
1 Zona Norte                            3549.
2 Madrid                                2240.
3 Zona Noroeste                         1817.
4 Cuenca del Tajo-Tajuña                 952.
5 Zona Sur                               902.
6 Corredor del Henares                   866.
7 Cuenca del Alberche-Guadarrama         760.
> select(zonas %>% arrange(price_avg), zone, price_avg)
# A tibble: 7 x 2
  zone                           price_avg
  <chr>                                 <dbl>
1 Cuenca del Alberche-Guadarrama         760.
2 Corredor del Henares                   866.
3 Zona Sur                               902.
4 Cuenca del Tajo-Tajuña                 952.
5 Zona Noroeste                         1817.
6 Madrid                                2240.
7 Zona Norte                            3549.
> select(zonas %>% arrange(-surface_avg), zone, surface_avg)
# A tibble: 7 x 2
  zone                           surface_avg
  <chr>                                     <dbl>
1 Zona Norte                                192. 
2 Zona Noroeste                             188. 
3 Cuenca del Tajo-Tajuña                    129. 
4 Cuenca del Alberche-Guadarrama            121. 
5 Madrid                                    117. 
6 Zona Sur                                  107. 
7 Corredor del Henares                       97.2
~~~



~~~
> select(villages %>% arrange(-total_vals), village, total_vals)
# A tibble: 428 x 2
   village                      total_vals
   <chr>                                <int>
 1 Zona Castellana                        178
 2 Zona Recoletos                         173
 3 Zona Universidad-Malasaña              167
 4 Zona Embajadores-Lavapiés              130
 5 Zona Justicia-Chueca                   130
 6 Zona Almagro                           119
 7 Zona Lista                             117
 8 Zona Argüelles                         107
 9 Zona Goya                              100
10 Zona Hispanoamérica-Bernabéu            96
# … with 418 more rows
> select(villages %>% arrange(-price_avg), village, price_avg)
# A tibble: 428 x 2
   village                              price_avg
   <chr>                                       <dbl>
 1 Pedrezuela                                112950 
 2 Zona Nueva España                          23240.
 3 Zona La Moraleja                            8307.
 4 Zona La Finca                               8259.
 5 Zona Monteclaro                             6675 
 6 Zona El Plantío                             6125.
 7 Carabaña                                    6000 
 8 Zona La Pizarra                             6000 
 9 Zona Urbanización Este-Montepríncipe        5663.
10 Zona Montealina                             5221.
# … with 418 more rows
> select(villages %>% arrange(price_avg), village, price_avg)
# A tibble: 428 x 2
   village             price_avg
   <chr>                      <dbl>
 1 Cervera de Buitrago         340 
 2 Tielmes                     348.
 3 Valdeavero                  400 
 4 Bustarviejo                 425 
 5 Corpa                       425 
 6 Batres                      450 
 7 Pelayos de la Presa         540 
 8 Puentes Viejas              550 
 9 Titulcia                    550 
10 Redueña                     568.
# … with 418 more rows
> select(villages %>% arrange(-surface_avg), village, surface_avg)
# A tibble: 428 x 2
   village                              surface_avg
   <chr>                                           <dbl>
 1 Zona Club de Golf                                796 
 2 Cabanillas de la Sierra                          750 
 3 Ciudalcampo                                      608.
 4 Zona La Finca                                    600.
 5 Madrid                                           600 
 6 Zona Urbanización Este-Montepríncipe             534 
 7 Zona Las Lomas                                   525.
 8 Zona Bonanza                                     524 
 9 Zona La Pizarra                                  500 
10 Zona Los Robles                                  452 
# … with 418 more rows
~~~



~~~
> select(companies %>% arrange(-total_vals), company, total_vals)
# A tibble: 1,036 x 2
   company                                          total_vals
   <chr>                                                    <int>
 1 NA                                                         488
 2 SERVICHECK (VALLECAS)                                      488
 3 INMOBILIARIA EMMANUEL                                      235
 4 aProperties                                                188
 5 Consultoría Inmobiliaria Internacional de Madrid           142
 6 DEAL INMOBILIARIA                                          117
 7 OUTLETDEVIVIENDAS                                          111
 8 RENTA GARANTIZADA - UMBER                                   90
 9 TESTA RESIDENCIAL                                           80
10 SOLFAI CONSULTING                                           77
# … with 1,026 more rows
> select(companies %>% arrange(-price_avg), company, precio_media)
# A tibble: 1,036 x 2
   company                                  price_avg
   <chr>                                           <dbl>
 1 REDPISO LAS TABLAS                            113432.
 2 INMOBILIARIA EMMANUEL                          10105.
 3 COLDWELL BANKER GLOBAL LUXURY ZAROSAN           9280 
 4 Vive Home Style                                 7371.
 5 ARRAS CONSULTORIA INMOBILIARIA                  7300 
 6 MADRID TEAM SL                                  7057.
 7 VOHOME CENTRAL                                  6900 
 8 GESTION MADRID                                  6850 
 9 ALFEREZ REAL ESTATE                             6250 
10 Berkashire Hathaway Home Services Larvia        6112.
# … with 1,026 more rows
> select(companies %>% arrange(price_avg), company, price_avg)
# A tibble: 1,036 x 2
   company                         price_avg
   <chr>                                  <dbl>
 1 INMOBILIARIA PULPON                     200 
 2 HOUSE FM                                300 
 3 DP 2020 GESTIONES INMOBILIARIAS         320 
 4 DISTRITO GETAFE I                       350 
 5 RED IN                                  390 
 6 ABANTOS ( ISABEL BEATRIZ )              412.
 7 CARIHUELA SOL                           450 
 8 GCI                                     450 
 9 CASA SERVICIOS INMOBILIARIOS            488.
10 BARCHAN                                 500 
# … with 1,026 more rows
> select(companies %>% arrange(-surface_avg), company, surface_avg)
# A tibble: 1,036 x 2
   company                                  surface_avg
   <chr>                                               <dbl>
 1 LÍNEA DE GESTIÓN 2, S.A.                             600 
 2 MIRANDA SERVICIOS INMOBILIARIOS.                     546.
 3 MIRAMADRID GRUPO                                     544 
 4 Rester Iberia                                        500.
 5 GESTION MADRID                                       500 
 6 Berkashire Hathaway Home Services Larvia             495.
 7 DOMUS VENDI                                          480 
 8 HOUSING4YOU                                          455 
 9 Mg Grupo Inmobiliario                                452 
10 2MP                                                  450 
# … with 1,026 more rows
~~~



~~~
> print("most common values")
[1] "most common values"
> # PRICE
> sort(table(mydata["price"]),decreasing=TRUE)[1:5]

1200 1100  900 1300  850 
 258  232  214  200  190 
> # REAL ESTATE COMPANIES
> sort(table(mydata["company"]),decreasing=TRUE)[1:5] # NA = independent owner renting his property(ies)

                                              NA                            SERVICHECK (VALLECAS) 
                                             488                                              488 
                           INMOBILIARIA EMMANUEL                                      aProperties 
                                             235                                              188 
Consultoría Inmobiliaria Internacional de Madrid 
                                             142 
> # SURFACE
> sort(table(mydata["surface"]),decreasing=TRUE)[1:5] # squared meters

 60  70  90  80 100 
262 255 221 208 192 
> # ROOMS
> sort(table(mydata["rooms"]),decreasing=TRUE)[1:3]

   2    3    1 
1811 1651 1388 
~~~

### Cluster analysis

~~~
> ds <- select(mydata, 4,5,6,7,9) # all of the numeric feats
> # KMEANS
> dcluster <- kmeans(ds, 6, nstart = 1)
> dcluster
K-means clustering with 6 clusters of sizes 1301, 19, 293, 1, 4499, 1

Cluster means:
        price   surface    rooms  toilets  numpics
1    2742.738 195.87087 3.450423 2.860876 26.18370
2   16500.000 289.31579 7.684211 7.894737 36.73684
3    5831.676 402.96928 5.051195 4.935154 32.50853
4 1800000.000 350.00000 5.000000 4.000000 14.00000
5    1134.665  90.35074 2.185819 1.530118 17.76039
6  450000.000 437.00000 4.000000 3.000000 58.00000
~~~



~~~
> group1 <- filter(mydata, price >250 & price < 1600)
> mean(data.matrix(group1["price"]))
[1] 1044.116
> sd(data.matrix(group1["price"]))
[1] 268.9029
~~~

![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/densitypricegroup1.png)


~~~
> shapiro.test(data.matrix(group1["price"]))

	Shapiro-Wilk normality test

data:  data.matrix(group1["price"])
W = 0.97499, p-value < 2.2e-16
~~~
So we can see that we don't have a normal distribution

~~~

~~~


~~~

~~~


~~~

~~~


~~~

~~~