
# ifconfig.pm

This is a slightly modified version of https://github.com/georgyo/ifconfig.io :
* Support for HTTP Connection, Charset, Via, Do-Not-Track and Cache-Control headers
* Added Protocol field
* Added a way to support real client port when the app is run behind a proxy
* wget and fetch are treated like curl (providing value without html formating)
* show IP country and AS number based on Maxmind geolite free database, using https://github.com/abh/geoip

Build instruction :
* install golang-go
* git clone https://github.com/pfoo/ifconfig.pm.git
* cd ifconfig.pm
* export GOPATH="`pwd`"
* go get -d -v
* go build

A few parameters can be defined using export before launching the binary :
* export GIN_MODE=debug|release
* export PORT="8081"
* export HOST="127.0.0.1"

Required for ip country and asn support :
* apt-get install geoip-bin geoip-database-contrib
* geoip-database-contrib_update
* You might need to adjust geoip databases location in main.go (lines 20-23) if you are not running debian

Running behind a proxy (usefull if you already have a webserver running on port 80) :
* Run the go program on 127.0.0.1:8081
* Use apache mod_proxy to proxy requests from apache to http://127.0.0.1:8081/
* Add followings headers to the proxyfied requests :<br>
	CF-Connecting-IP : The IP address the client is connecting from. Important or the IP will be wrong.<br>
	CF-Connecting-PORT : The port the client is connecting from. Important or the PORT will be wrong.<br>
	CF-Connection : HTTP_CONNECTION header sent by the client to the proxy<br>
* See example apache.conf

#### ORIGINAL README FROM https://github.com/georgyo/ifconfig.io :

Inspired by ifconfig.me, but designed for pure speed. A single server can do 18,000 requests per seconds while only consuming 50megs of ram.

I used the gin framework as it does several things to ensure that there are no memory allocations on each request, keeping the GC happy and preventing unnessary allocations.

Tested to handle 15,000 requests persecond on modest hardware with an adverage response time of 130ms.
![LoadTest](http://i.imgur.com/xgR4u1e.png)
