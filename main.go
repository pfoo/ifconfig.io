package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-systemd/activation"
	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
)

// open geolite country database (download from https://dev.maxmind.com/geoip/geoip2/geolite2/)
var DBCountry, DBCountryerr = maxminddb.Open("GeoLite2-Country.mmdb")

// open geolite ASN database (download from https://dev.maxmind.com/geoip/geoip2/geolite2/)
var DBASN, DBASNerr = maxminddb.Open("GeoLite2-ASN.mmdb")

// struct for country db
var RecordCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"` // get country iso code
		Names struct {
			Name string `maxminddb:"en"` // get country name in english (en)
		} `maxminddb:"names"`
	} `maxminddb:"country"`

}

// struct for asn db
var RecordASN struct {
	ASNumber int `maxminddb:"autonomous_system_number"`
	ASName string `maxminddb:"autonomous_system_organization"`
}

// Logger is a simple log handler, out puts in the standard of apache access log common.
// See http://httpd.apache.org/docs/2.2/logs.html#accesslog
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		ip, err := net.ResolveTCPAddr("tcp", c.Request.RemoteAddr)
		if err != nil {
			c.Abort()
		}

		// before request
		c.Next()
		// after request

		user := "-"
		if c.Request.URL.User != nil {
			user = c.Request.URL.User.Username()
		}

		latency := time.Since(t)

		// This is the format of Apache Log Common, with an additional field of latency
		fmt.Printf("%v - %v [%v] \"%v %v %v\" %v %v %v\n",
			ip.IP, user, t.Format(time.RFC3339), c.Request.Method, c.Request.URL.Path,
			c.Request.Proto, c.Writer.Status(), c.Request.ContentLength, latency)
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func mainHandler(c *gin.Context) {
	fields := strings.Split(c.Params.ByName("field"), ".")
	ip, err := net.ResolveTCPAddr("tcp", c.Request.RemoteAddr)
	if err != nil {
		c.Abort()
	}

	//proxy handling stuff

	// use CF-Connecting-IP header as ip if available (this means app is invoked behind a proxy)
	cfIP := net.ParseIP(c.Request.Header.Get("CF-Connecting-IP"))
	if cfIP != nil {
		ip.IP = cfIP
	}

	// use CF-Connecting-PORT header as source port if available (this means app is invoked behind a proxy)
	cfPORT := c.Request.Header.Get("CF-Connecting-PORT")
	if cfPORTnum, err := strconv.Atoi(cfPORT); err == nil {
		ip.Port = cfPORTnum
	}

	// Use CF-Connection header instead of HTTP Connection header if available (this means app is invoked behind a proxy)
	ConnectionHeader := c.Request.Header.Get("Connection")
	if cfCONN := c.Request.Header.Get("CF-Connection"); cfCONN != "" {
		ConnectionHeader = cfCONN
	}

	// AS number and country name stuff
	var geoip_country, geoip_asn string
	err = DBCountry.Lookup(ip.IP, &RecordCountry)
	if err != nil {
		log.Fatal(err)
	}
	geoip_country = RecordCountry.Country.Names.Name
	err = DBASN.Lookup(ip.IP, &RecordASN)
	if err != nil {
		log.Fatal(err)
	}
	geoip_asn = RecordASN.ASName+" (AS"+strconv.Itoa(RecordASN.ASNumber)+")"

	// Use CF-Protocol header as protocol if available instead default gathered protocol (this means app is invoked behind a proxy)
	Protocol := c.Request.Proto
	if cfProto := c.Request.Header.Get("CF-Protocol"); cfProto != "" {
		Protocol = cfProto
	}

	c.Set("ip", ip.IP.String())
	c.Set("port", ip.Port)
	c.Set("ua", c.Request.UserAgent())
	c.Set("protocol", Protocol)
	c.Set("lang", c.Request.Header.Get("Accept-Language"))
	c.Set("encoding", c.Request.Header.Get("Accept-Encoding"))
	c.Set("method", c.Request.Method)
	c.Set("connection", ConnectionHeader)
	c.Set("mime", c.Request.Header.Get("Accept"))
	c.Set("charset", c.Request.Header.Get("Accept-Charset"))
	c.Set("referer", c.Request.Header.Get("Referer"))
	c.Set("via", c.Request.Header.Get("Via"))
	c.Set("forwarded", c.Request.Header.Get("X-Forwarded-For"))
	//c.Set("country", c.Request.Header.Get("CF-IPCountry")) //determine country using provided header
	c.Set("country", geoip_country)
	r := strings.NewReplacer("0", "No", "1", "Yes")
	c.Set("dnt", r.Replace(c.Request.Header.Get("DNT")))
	c.Set("cache", c.Request.Header.Get("cache-control"))
	c.Set("asn", geoip_asn)

	ua := strings.Split(c.Request.UserAgent(), "/")

	// Only lookup hostname if the results are going to need it.
	if stringInSlice(fields[0], []string{"all", "host"}) || (fields[0] == "" && ua[0] != "curl" && ua[0] != "Wget" && ua[0] != "fetch") {
		hostnames, err := net.LookupAddr(ip.IP.String())
		if err != nil {
			c.Set("host", "")
		} else {
			c.Set("host", hostnames[0])
		}
	}

	wantsJSON := false
	if len(fields) >= 2 && fields[1] == "json" {
		wantsJSON = true
	}

	switch fields[0] {
	case "":
		//If the user is using curl, wget or fetch, then we should just return the IP, else we show the home page.
		if ua[0] == "curl" || ua[0] == "Wget" || ua[0] == "fetch" {
			c.String(200, fmt.Sprintln(ip.IP))
		} else {
			c.HTML(200, "index.html", c.Keys)
		}
		return
	case "request":
		c.JSON(200, c.Request)
		return
	case "all":
		if wantsJSON {
			c.JSON(200, c.Keys)
		} else {
			c.String(200, "%v", c.Keys)
		}
		return
	}

	fieldResult, exists := c.Get(fields[0])
	if !exists {
		c.String(404, "Not Found")
		return
	}
	c.String(200, fmt.Sprintln(fieldResult))

}

func main() {

	if DBCountryerr != nil {
		log.Fatal(DBCountryerr)
		os.Exit(1)
	}
	defer DBCountry.Close()

	if DBASNerr != nil {
		log.Fatal(DBASNerr)
		os.Exit(1)
	}
	defer DBASN.Close()

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(Logger())
	r.LoadHTMLGlob("templates/*")

	r.GET("/:field", mainHandler)
	r.GET("/", mainHandler)

	// Used for FCGI listener and systemd socket
	errc := make(chan error)
	go func(errc chan error) {
		for err := range errc {
			panic(err)
		}
	}(errc)

	// Create the FCGI listener
	fcgi_listen, err := net.Listen("tcp", "127.0.0.1:4000")
	if err != nil {
		panic(err)
	}
	go func(errc chan error) {
		errc <- fcgi.Serve(fcgi_listen, r)
	}(errc)

	// Create the systemd socket listener (port provided by systemd)
	listeners, err := activation.Listeners()
	if err != nil {
		fmt.Printf("Could not get systemd listerns with err %q", err)
	}
	for _, listener := range listeners {
		go func(errc chan error) {
			errc <- http.Serve(listener, r)
		}(errc)
	}

	// HTTP listener
	port := os.Getenv("PORT")
	host := os.Getenv("HOST")
	if port == "" {
		port = "8080"
	}
	errc <- r.Run(host + ":" + port)
}
