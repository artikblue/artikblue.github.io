---
layout: post
title:  "Async programming made easy with python asyncio"
author: artikblue
categories: [ python, programming ]
tags: [python, asyncio, apis]
image: assets/images/arduino/pservo.jpg
description: "Learning how to deal with async programming with python."
featured: true
---

Good morning warriors of the code! Today I'm going to walk you through the misteries of asyncronous programming with python using the world known asyncio library :)

#### About async programming

![definition](https://artikblue.github.io/assets/images/asyncio/definition.jpg)

![loop](https://artikblue.github.io/assets/images/asyncio/eventloop.png)


#### Hello world(s)
~~~
import asyncio

async def say(what, when):
    await asyncio.sleep(when)
    print(what)

loop = asyncio.get_event_loop()
loop.run_until_complete(say('hello world', 1))
loop.close()
~~~

~~~
import asyncio

async def say(what, when):
    await asyncio.sleep(when)
    print(what)


loop = asyncio.get_event_loop()

loop.create_task(say('first hello', 2))
loop.create_task(say('second hello', 1))

loop.run_forever()
loop.close()
~~~

#### Task optimization using asyncio

##### Sync code

~~~
import datetime
import colorama
import random
import time


def main():
    t0 = datetime.datetime.now()
    print(colorama.Fore.WHITE + "App started.", flush=True)
    data = []
    generate_data(20, data)
    process_data(20, data)

    dt = datetime.datetime.now() - t0
    print(colorama.Fore.WHITE + "App exiting, total time: {:,.2f} sec.".format(dt.total_seconds()), flush=True)


def generate_data(num: int, data: list):
    for idx in range(1, num + 1):
        item = idx*idx
        data.append((item, datetime.datetime.now()))

        print(colorama.Fore.YELLOW + f" -- generated item {idx}", flush=True)
        time.sleep(random.random() + .5)


def process_data(num: int, data: list):
    processed = 0
    while processed < num:
        item = data.pop(0)
        if not item:
            time.sleep(.01)
            continue

        processed += 1
        value = item[0]
        t = item[1]
        dt = datetime.datetime.now() - t

        print(colorama.Fore.CYAN +
              " +++ Processed value {} after {:,.2f} sec.".format(value, dt.total_seconds()), flush=True)
        time.sleep(.5)


if __name__ == '__main__':
    main()
~~~

##### Async code
~~~
import datetime
import colorama
import random
import asyncio

# Greetz to talkpython for this one :)

def main():
    t0 = datetime.datetime.now()
    print(colorama.Fore.WHITE + "App started.", flush=True)

    loop = asyncio.get_event_loop()
    data = asyncio.Queue()

    task1 = loop.create_task(generate_data(20, data))
    task3 = loop.create_task(generate_data(20, data))
    # task4 = loop.create_task(generate_data(20, data))
    task2 = loop.create_task(process_data(40, data))

    final_task = asyncio.gather(task1, task2, task3)
    loop.run_until_complete(final_task)

    dt = datetime.datetime.now() - t0
    print(colorama.Fore.WHITE + "App exiting, total time: {:,.2f} sec.".format(dt.total_seconds()), flush=True)


async def generate_data(num: int, data: asyncio.Queue):
    for idx in range(1, num + 1):
        item = idx*idx
        await data.put((item, datetime.datetime.now()))

        print(colorama.Fore.YELLOW + f" -- generated item {idx}", flush=True)
        await asyncio.sleep(random.random() + .5)


async def process_data(num: int, data: asyncio.Queue):
    processed = 0
    while processed < num:
        item = await data.get()

        processed += 1
        value = item[0]
        t = item[1]
        dt = datetime.datetime.now() - t

        print(colorama.Fore.CYAN +
              " +++ Processed value {} after {:,.2f} sec.".format(value, dt.total_seconds()), flush=True)
        await asyncio.sleep(.5)


if __name__ == '__main__':
    main()
~~~

#### Making non-async functions async

~~~
import decimal
import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor
def force_async(fn):
    '''
    turns a sync function to async function using threads
    '''
    from concurrent.futures import ThreadPoolExecutor
    import asyncio
    pool = ThreadPoolExecutor()

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        future = pool.submit(fn, *args, **kwargs)
        return asyncio.wrap_future(future)  # make it awaitable

    return wrapper

@force_async
def compute_pi(n):
    decimal.getcontext().prec = n + 1
    C = 426880 * decimal.Decimal(10005).sqrt()
    K = 6.
    M = 1.
    X = 1
    L = 13591409
    S = L
    for i in range(1, n):
        M = M * (K ** 3 - 16 * K) / ((i + 1) ** 3)
        L += 545140134
        X *= -262537412640768000
        S += decimal.Decimal(M * L) / X
    pi = C / S
    return str(pi)

async def greet(msg):
    print(msg)    

async def print_pi(dec):
    pi = await compute_pi(dec)
    print(pi)

print("Now, compute_pi will be executed")

loop = asyncio.get_event_loop()
data = asyncio.Queue()

task1 = loop.create_task(print_pi(800))
task2 = loop.create_task(greet("Another function gets calleeeeeeed"))
task3 = loop.create_task(greet("Another function gets called"))

final_task = asyncio.gather( task1,task2, task3)
loop.run_until_complete(final_task)
~~~

#### Async flask with quart

~~~
import asyncio
import aiohttp # python async equiv of requests
async def planets(n):
    
    async with aiohttp.ClientSession() as session:
        async with session.get(api+"planets/"+str(n)) as resp:
            resp.raise_for_status()
            return await resp.text()

    return resp.json
~~~

~~~
import quart
@blueprint.route('/planet/<n>', methods=['GET'])
async def planet(n: str):
    planet = await starwars.planets(n)

    return quart.jsonify(planet)
~~~

#### Sources

[python 3.8 asyncio guide by integralist](https://www.integralist.co.uk/posts/python-asyncio/)
  
[asyncio docs](https://asyncio.readthedocs.io/en/latest/hello_world.html)  

[talkpython trainings](https://training.talkpython.fm/)
  
[my github](https://github.com/artikblue/100DaysOfWeb/tree/master/21-24-quart-async)