---
layout: post
title:  Async programming made easy with python asyncio
tags: python asyncio apis
image: '/images//asyncio/head.jpeg'
date: 2020-01-19 15:01:35 -0700
---

Good morning warriors of the code! Today I'm going to walk you through the misteries of asyncronous programming with python using the world known asyncio library :)

#### About async programming wyth python
Parallel programming can be understood with the following image:
![definition](https://artikblue.github.io/assets/images/asyncio/definition.jpg)

Understanding the concept of parallel programming is quite simple. In traditional programs, one instruction comes after another, so first you run the process a, then maybe starting with the result of process a you run process b and so on, one after another. But think about of the following task, one program executes an operation to retrieve data from the network, it has to wait for the data and then do some other things, some of them may depend on the received data and some others not, the program could be executing those processes that do not depend on that data meanwhile the other process waits for the data, that can be done in parallel and in fact is one of the classical problems that python asyncio solves. Another classical program relates to the following problem: Imagine that you have a massive excel table containing tag: value and value is a numeric value, you have to ADD all of those values one by one, you sure can add the first to the second, then add the result to the third one and so on but, if you happen to have another processor on your system you could easily split the table in two (or tell the other processor to start at the n/2 position) and let each processor add its set of values one by one, then at the end add the two results together and get the final value, if you have X processors you can n/x split your data set and perform x times faster :) that case unluckly does not relate so well to python asyncio :(  

Basically because python does not support multiprocessor/multicore operations, so all of its async operations are executed on a single thread by a "polling" system.

![definition](https://artikblue.github.io/assets/images/asyncio/poll.png)

A polling system in this case, is a loop that goes process by process every X time, very quickly and "asks" about the result of an operation and or runs some code. Single cpu single core systems work 100% this way eventhough you have the feeling that many programs are going on at the same time (ex: browser, text editor and music player).  

Asyncio works this way as you can see in the following diagram:
![loop](https://artikblue.github.io/assets/images/asyncio/eventloop.png)
The program starts with a main loop, tasks are executed in order, each task is executed until it has to "await" for something, then the next one doing the same till it reaches the last one and from there back to the beginning.

#### Hello world(s)
The simplest program you can write using asyncio is this one here:
~~~
import asyncio

async def say(what, when):
    await asyncio.sleep(when)
    print(what)

loop = asyncio.get_event_loop()
loop.run_until_complete(say('hello world', 1))
loop.close()
~~~
It basically defines the say() function as an async funcion. That function will async wait N seconds and then print a message. Then it moves that function to the event loop and runs the loop. That function is defined as an async function because it uses the await statement. As it is defined as an "async" function it also have to be awaited. Asyncio.sleep does the same thing as time.sleep, it just "pauses" the execution N seconds. The main difference with time.sleep is that asyncio.sleep will be executed asyncronously and thus will "generate an interruption" after N seconds, that interruption will be "received" by the main loop and then the print will be executed. The key concept here is that the print will only be executed AFTER the sleep call because it has an await statement before and so the process will AWAIT for the result before continuing.  
 
But meanwhile that process is "awaiting" some other process can run!  

Let's look at this one :)
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
In this case we insert a couple of tasks in the loop, two processes that come from the same function, one will wait two seconds, one will wait 1. It is very clear that in a standard sync program the execution time will be about 3 seconds, in here it will be about 2. So in here, the first process will be executed and so will get to sleep for two seconds, after the first process gets to sleep the "execution flow" will be liberated and the program will proceed with the second process, that one will be waiting for one second, so it will "wake up" clearly before the first process or in other terms, when the second process would awake it the first one will still be sleeping and thus the execution flow will be free, it will run the print and then after one second the first process will wake up and run its print!
#### Task optimization using asyncio
That was very simple though. We have to keep in mind that processes that are using this scheme can work together even sharing resources. Of course as you may think, by using this new feature, more complex algorithms can be implemented.  

A typical example of a complex async scenario with a common resource that is shared can be the following. Imagine that you have a couple of processes, one process generates some data and based on that data, the other one performs a task. Data can be "batch" generated, so on a sync program first, one process will generate a certain amount of data, then the other process will go through that data and perform the task. That can be really slow, basically because the second task will only kick after the first one finishes. A more optimal scenario will process the data as soon as its available!
  
Now imagine that this is the sync program:
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
In the previous example, we can clearly identify the "data" queue as the resource that contains data in both functions. Time sleep is the function that can be awaited, so meanwhile one process is sleeping the other one can pick up data from the queue and start processing it.  

The following code does that:
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
Those examples were very good for understanding the underlying concept of asyncio but you may be wondering about using asyncio with real functions, not only built in functions such as asyncio.sleep and such.  

Well, to go straight to the point, the following wrapper uses threads to convert a sync function to an async one. Just note that if you define a function as an async, that function needs to be called from an async function or needs to be called as a task and inserted somehow in the loop.  

The following function will compute PI asyncronously.
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
Another clear example of the benefits of parallel/async programming is found in APIs/Backends. If you have a web service that will eventually run complex and time consuming operations such as heavy db queries or complex operations each request will be time consuming and if you have a large number of requests those will stack up slowing the system or even collapsing it.  

The Quart framework extends the Flask [Flask](https://palletsprojects.com/p/flask) implenting asyncio over it. Its workflow is super simple, the functions that will get executed in each of the api endpoints are defined as async and thus can work with async functions unlocking the execution flow for other calls to be executed while they wait for some process to complete! :)  

A function can be defined somewhere in the project:
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
Then called in the api view asyncronously:
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