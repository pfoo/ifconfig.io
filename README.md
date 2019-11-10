
# ifconfig.pm

## README

This is a slightly modified version of https://github.com/georgyo/ifconfig.io :
* Support for HTTP Connection, Charset, Via, Do-Not-Track and Cache-Control headers
* Added Protocol field and a way of displaying the original protocol if running behind an HTTP proxy 
* Added a way to support real client port when the app is run behind an HTTP proxy
* wget and fetch are treated like curl (providing value without html formating)
* show IP country and AS name/number based on MaxMind GeoLite2 free database using https://github.com/oschwald/maxminddb-golang

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

Required for ip country and ASN support :
* Download databases from https://dev.maxmind.com/geoip/geoip2/geolite2/ and place GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb on the same directory than the binary.

Running behind an HTTP proxy (usefull if you already have a webserver running on port 80) :
* Run the go program on 127.0.0.1:8081
* Use apache mod_proxy_http to proxy requests from apache to http://127.0.0.1:8081/
* Add followings headers to the proxyfied requests :<br>
	CF-Connecting-IP : The IP address the client is connecting from. Important or the IP will be wrong.<br>
	CF-Connecting-PORT : The port the client is connecting from. Important or the PORT will be wrong.<br>
	CF-Connection : HTTP_CONNECTION header sent by the client to the proxy<br>
	CF-Protocol : The HTTP protocol the client is connecting with. Important or the displayed protocol will be wrong.<br>
* See example apache.http.conf

Running behind an FCGI proxy :
* Use apache mod_proxy_fcgi to proxy requests from apache to fcgi://127.0.0.1:4000/
* See example apache.fcgi.conf

#### ORIGINAL README FROM https://github.com/georgyo/ifconfig.io :

Inspired by ifconfig.me, but designed for pure speed. A single server can do 18,000 requests per seconds while only consuming 50megs of ram.

I used the gin framework as it does several things to ensure that there are no memory allocations on each request, keeping the GC happy and preventing unnessary allocations.

Tested to handle 15,000 requests persecond on modest hardware with an adverage response time of 130ms.
![LoadTest](http://i.imgur.com/xgR4u1e.png)
