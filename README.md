
# ifconfig.pm

This is a slightly modified version of https://github.com/georgyo/ifconfig.io :
* Support for HTTP Connection, Charset, Via, Do-Not-Track and Cache-Control headers
* Added a way to support real client port when the app is run behind a proxy
* wget and fetch are treated like curl (providing value without html formating)

Build instruction :
* 

Running behind a proxy :
* 

ORIGINAL README FROM https://github.com/georgyo/ifconfig.io

Inspired by ifconfig.me, but designed for pure speed. A single server can do 18,000 requests per seconds while only consuming 50megs of ram.

I used the gin framework as it does several things to ensure that there are no memory allocations on each request, keeping the GC happy and preventing unnessary allocations.

Tested to handle 15,000 requests persecond on modest hardware with an adverage response time of 130ms.
![LoadTest](http://i.imgur.com/xgR4u1e.png)
