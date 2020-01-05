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
## Data analysis
Today I'm working with the data that I gathered from "habitaclia.com", related to the flat renting market in Madrid. Find this data here(https://github.com/artikblue/datasets-analyses)  
In this post I will walk you a little bit through the data I gathered:
### Basic data analysis
As the dataset is stored in a mongo db the first step is connecting to it and retrieving the collection.
~~~
> con <- mongo("realestate_renting", url = "mongodb://127.0.0.1:27017/habitaclia")
> con$count()
[1] 6114
~~~
We can see that our dataset is composed by a total of 6114 flat renting offers.  
With the dataset loaded we can start by doing some basic descriptive statistics. As it is important to know about what data we are doing our analysis we can print the urban areas and the villages were the offers we just retrieved belong.
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
As we are doing our analysis on the real estate renting market one obviously interesting thing to know is the avg renting price and the avg surface. As we are dealing with a lot of offers and some of them (specially the luxuriy properties) can have a very high price, using the median here is interesting and more revealing.
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
And done that, we can notice an interesting difference between the median and the mean.  
Box plots are also quite interesting and somehow confirm the theory I just presented. The boxplot related to the price shows that almost all values are between a specific range and then some outliers appear in the upper sector, so those are luxury properties for sure.
![priceboxplot](https://artikblue.github.io/images/blog/madrid_renting/priceboxplot.png)
Regarding to the surface something similar happens but not as extreme, probably because expensive properties are more about luxury than just "space".
![surfaceboxplot](https://artikblue.github.io/images/blog/madrid_renting/boxplotsurface)
Those two other boxplots I think are quite less relevant and follow the same logic.

![roomsboxplot](https://artikblue.github.io/images/blog/madrid_renting/boxplotrooms.png)

![toiletsboxplot](https://artikblue.github.io/images/blog/madrid_renting/boxplottoilets.png)

We can also generate the density graphs for each feat to quickly identify if they follow a normal distribution along all of the elements.  
In the first graph, related to the price we can see that almost all of the values are concentrated at the very beggining and so the outliers have a big effect on "breaking" the normality.  


![pricedensity](https://artikblue.github.io/images/blog/madrid_renting/densityprice.png)

Regarding to the surface all of the values are located between about 30 and 200 which is somehow expected, then we may have some very big properties but not to many.


![surfacedensity](https://artikblue.github.io/images/blog/madrid_renting/surfacedensity.png)
The rooms and toilets follow the same logic, we see that the graphic is fluctuating because we have few "integer" values of each like 1,2,3... and all of the elements match at least in one category.
![roomsdensity](https://artikblue.github.io/images/blog/madrid_renting/roomsdensity.png)

![toiletsdensity](https://artikblue.github.io/images/blog/madrid_renting/toiletsdensity.png)

As a conclusion of this first stage of the analysis a summary of the data can complete this big picture for us:
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
From the data summary we can basically extract that prices range from 200EUR to 1800000EUR the avg house/flat may have a cost I would say between 1300EUR and 2000EUR and it would have a surface between 92m2 and 100m2 and would have 1 toilet and 2 or 3 rooms. Most of the offer posts include 18 pics. There is nothing much more to extract.  
We can also try to identify some correlation between features by generating the pairs graph.
![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/basicpairs.png)
One can guess that price and surface may have correlation but price may depend on other factors such as location or luxury. In other terms price and surface have correlation but at the very beggining of the scale, then other factors come to play .Of course surface and rooms and toilets have correlation.
### Analysis by categories
As the offers belong to specif categories such as zone or or village, we can try groping our data by those and exploring the differences between each.
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
Then we can analyze the zones who have more offers, the more expensive zones and the zones who offer larger spaces:
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
> select(zones %>% arrange(-price_avg), zone, price_avg)
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
Not a big surpise that most of the offers are located in the metropolital area (aka the big city). Another interesting fact here is that living in small villages outside the metropilitan area can be very cheap.  
If we go by village (or quarter in the big city) we see that most of the offers are located in the very city centre.
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
We can also note that the most expensive properties are located in the peripheria of the big city in luxury districts.  
The other interesting category here is the one related to companies:
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
We can see that SERVICHECK and EMMANUEL are the top offering companies and we can also identify potential luxury companies such as MIRANDA, LINDEA DE GESTIÓN and REDPISO LAS TABLAS.  
Seen that, we can end our general analysis by looking at the most common values on each category:
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
As we saw before, most of the prices range from 900 to 1300 and surfaces go from 60 to 100.
### Cluster analysis
As we saw in the first stage of this analysis, it is clear that we have different "categories" of properties (ex: rural vs urban, luxury vs affordable etc). In these situations running a cluster analysis can be helpful.
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
In this case a cluster analysis is a bit revealing as it shows multiple categories. From those categories one of them (number 5) clearly corresponds to the category we just defined in the previous stage. Other categories correspond to (probably) other significant market sectors such as categories 1 and 3. The rest of the categories correspond to highly expensive properties I can't even dream of.  
  
So having those identified, we can extract them from the general dataset.
~~~
> group1 <- filter(mydata, price >250 & price < 1600)
> mean(data.matrix(group1["price"]))
[1] 1044.116
> sd(data.matrix(group1["price"]))
[1] 268.9029
~~~
And repeat our analyses focused on each group:
![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/densitypricegroup1.png)


~~~
> shapiro.test(data.matrix(group1["price"]))

	Shapiro-Wilk normality test

data:  data.matrix(group1["price"])
W = 0.97499, p-value < 2.2e-16
~~~
So we can see that we don't have a normal distribution in terms of the price eventhough there is more "normality" here than in the general group.

![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/group1pairs.png)
It is very interesting to note here that as we move to this general group (let's say the avg property for the avg family) we can appreciate how in here price and surface do really correlate somehow.


![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/group1regression.png)

~~~
> regresion = lm(data.matrix(group1["price"]) ~ data.matrix(group1["surface"])) 
> plot(price ~ surface, group1)
> abline (regresion, lwd=1, col ="red" )    
> regresion

Call:
lm(formula = data.matrix(group1["price"]) ~ data.matrix(group1["surface"]))

Coefficients:
                   (Intercept)  data.matrix(group1["surface"])  
                       891.924                           1.807  

> cor.test(data.matrix(group1["surface"]), data.matrix(group1["price"]), method=c("pearson", "kendall", "spearman"))

	Pearson's product-moment correlation

data:  data.matrix(group1["surface"]) and data.matrix(group1["price"])
t = 20.224, df = 3902, p-value < 2.2e-16
alternative hypothesis: true correlation is not equal to 0
95 percent confidence interval:
 0.2793456 0.3361389
sample estimates:
      cor 
0.3080166 
~~~
Anyway correlation is still weak here.  
  
Let's go for the second group, expensive properties.

~~~
> group2 <- filter(mydata, price > 1600 & price < 3200)
> mean(data.matrix(group2["price"]))
[1] 2234.894
> sd(data.matrix(group2["price"]))
[1] 419.5886
~~~
![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/group2density.png)
We have a small degree of normality here but most of the properties range from 1500 to 2000.
~~~
> shapiro.test(data.matrix(group2["price"]))

	Shapiro-Wilk normality test

data:  data.matrix(group2["price"])
W = 0.93823, p-value < 2.2e-16
~~~
Anyway, we can see that we don't have a normal distribution here either.

![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/group2pairs.png)

![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/group2regression.png)
~~~
> pairs(~price + surface + rooms + toilets,data=group2,
+       main="correlation matrix") #Matríz de correlaciones
> regresion = lm(data.matrix(group2["price"]) ~ data.matrix(group2["surface"])) ## Construyo una ecuación de regresión lineal
> plot(price ~ surface, group2)
> abline (regresion, lwd=1, col ="red" )    ### Dibujo la línea de regresión
> regresion

Call:
lm(formula = data.matrix(group2["price"]) ~ data.matrix(group2["surface"]))

Coefficients:
                   (Intercept)  data.matrix(group2["surface"])  
                      1959.305                           1.724  

> cor.test(data.matrix(group2["price"]), data.matrix(group2["price"]), method=c("pearson", "kendall", "spearman"))

	Pearson's product-moment correlation

data:  data.matrix(group2["price"]) and data.matrix(group2["price"])
t = Inf, df = 1414, p-value < 2.2e-16
alternative hypothesis: true correlation is not equal to 0
95 percent confidence interval:
 1 1
sample estimates:
cor 
  1 
~~~
We still have a bit more regression here than in the general group, but its more weird than the previous group.  

And at the end we can categorize our elements and see how each group represents a % of the total.
~~~
> mydata$price_category<-ifelse(mydata$price <500, "VERYCHEAP", ifelse(mydata$price <1000,"NORMAL", ifelse(mydata$price < 5000,"EXPENSIVE","HIGHEXPENSIVE")))
> nrow(subset(mydata,price_category == "VERYCHEAP")) / nrow(mydata)
[1] 0.007360157
> nrow(subset(mydata,price_category == "NORMAL")) / nrow(mydata)
[1] 0.2924436
> nrow(subset(mydata,price_category == "EXPENSIVE")) / nrow(mydata)
[1] 0.6640497
> nrow(subset(mydata,price_category == "HIGHEXPENSIVE")) / nrow(mydata)
[1] 0.03614655
~~~
And we see how most of the properties belong to the "EXPENSIVE" category.  
### Predictive analysis
Can we predict the price of a property based on its features? Well, let's be honest, probably NOT. But we can try that anyway.
  
Neuralnet package offers a nice way to do that. We can select all of the numerical feats of our dataset, split the dataset into 60-40 for training and validation and run some tests.
~~~
library(neuralnet)
ds <- select(mydata, 4,5,6,7,9) 
dvals <- ds
samplesize <-0.60 * nrow(dvals)
set.seed(80)
index = sample(seq_len(nrow(ds)),size = samplesize)

datatrain = dvals[ index, ]
datatest = dvals[ -index, ]

max = apply(dvals , 2 , max)
min = apply(dvals, 2 , min)
scaled = as.data.frame(scale(dvals, center = min, scale = max - min))

trainNN = scaled[index , ]
testNN = scaled[-index , ]

# fit neural network price
set.seed(2)
NN = neuralnet(price ~ toilets + surface + rooms , trainNN, hidden = c(4,3,4) , linear.output = T )

# plot neural network
plot(NN)
~~~
We can even plot the neuralnetwork. And as we see the error is so high.
![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/neuralnet.png)
And we can plot the regression as well:
~~~
predict_testNN = compute(NN, testNN[,c(1:4)])
predict_testNN = (predict_testNN$net.result * (max(dvals$price) - min(dvals$price))) + min(dvals$price)

plot(datatest$price, predict_testNN, col='blue', pch=16, ylab = "predicted price NN", xlab = "real price")

abline(0,1)
~~~
It looks like we have a straight regression but... note that due to that outlier the scale moves a lot... so....
![basicpairs](https://artikblue.github.io/images/blog/madrid_renting/neuralregression.png)
We can calculate the RMSE:
~~~
> # Calculate Root Mean Square Error (RMSE)
> RMSE.NN = (sum((datatest$price - predict_testNN)^2) / nrow(datatest)) ^ 0.5
> RMSE.NN
[1] 9128.876
~~~
And it shows that the error is really high...!  
I will update this post soon with more interesting conclusions :)