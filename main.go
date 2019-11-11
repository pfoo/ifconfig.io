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
	"sync"
	"github.com/coreos/go-systemd/activation"
	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
)

// Databases path (download from https://dev.maxmind.com/geoip/geoip2/geolite2/)
var DBCountryPath = "GeoLite2-Country.mmdb"
var DBASNPath = "GeoLite2-ASN.mmdb"

// init global database variables for GeoIP
var DBCountry *maxminddb.Reader
var DBASN *maxminddb.Reader

// struct for Country database
var RecordCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"` // get country iso code
		Names struct {
			Name string `maxminddb:"en"` // get country name in english (en)
		} `maxminddb:"names"`
	} `maxminddb:"country"`

}

// struct for ASN database
var RecordASN struct {
	ASNumber int `maxminddb:"autonomous_system_number"`
	ASName string `maxminddb:"autonomous_system_organization"`
}

// Logger is a simple log handler, outputs in the standard of apache commn access log
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

	// use CF-Connecting-IP header as ip if available (this means app is invoked behind an HTTP proxy)
	cfIP := net.ParseIP(c.Request.Header.Get("CF-Connecting-IP"))
	if cfIP != nil {
		ip.IP = cfIP
	}

	// use CF-Connecting-PORT header as source port if available (this means app is invoked behind an HTTP proxy)
	cfPORT := c.Request.Header.Get("CF-Connecting-PORT")
	if cfPORTnum, err := strconv.Atoi(cfPORT); err == nil {
		ip.Port = cfPORTnum
	}

	// Use CF-Connection header instead of HTTP Connection header if available (this means app is invoked behind an HTTP proxy)
	ConnectionHeader := c.Request.Header.Get("Connection")
	if cfCONN := c.Request.Header.Get("CF-Connection"); cfCONN != "" {
		ConnectionHeader = cfCONN
	}

	// AS number and country name stuff
	var GeoIPCountry, GeoIPASN string
	err = DBCountry.Lookup(ip.IP, &RecordCountry)
	if err != nil {
		log.Panic(err)
	}
	GeoIPCountry = RecordCountry.Country.Names.Name+" ("+RecordCountry.Country.ISOCode+")"
	err = DBASN.Lookup(ip.IP, &RecordASN)
	if err != nil {
		log.Panic(err)
	}
	GeoIPASN = RecordASN.ASName+" (AS"+strconv.Itoa(RecordASN.ASNumber)+")"

	// Use CF-Protocol header as protocol if available instead default gathered protocol (this means app is invoked behind an HTTP proxy)
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
	c.Set("country", GeoIPCountry)
	DNTReplace := strings.NewReplacer("0", "No", "1", "Yes")
	c.Set("dnt", DNTReplace.Replace(c.Request.Header.Get("DNT")))
	c.Set("cache", c.Request.Header.Get("cache-control"))
	c.Set("asn", GeoIPASN)

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
//	case "request":
//		c.JSON(200, c.Request)
//		return
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
		c.String(404, fmt.Sprintln("404 Page Not Found"))
		return
	}
	c.String(200, fmt.Sprintln(fieldResult))
}

func main() {
	var err error

	// open Country database and defer closing to end of main()
	DBCountry, err = maxminddb.Open(DBCountryPath)
	if err != nil {
		log.Fatalf("Fatal: %v. Exiting.", err)
	}
	defer DBCountry.Close()

	// open ASN database and defer closing to end of main()
	DBASN, err = maxminddb.Open(DBASNPath)
	if err != nil {
		log.Fatalf("Fatal: %v. Exiting.", err)
	}
	defer DBASN.Close()

	// gin HTTP init with Recovery middleware and custom Logger
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(Logger())
//	router.LoadHTMLGlob("templates/*")
	router.LoadHTMLFiles("templates/index.html")

	// GET requests to / or /whatever is handled by mainHandler()
	router.GET("/:field", mainHandler)
	router.GET("/", mainHandler)

	// PUT requests to / or /whatever is handled by mainHandler()
	//router.PUT("/:field", mainHandler)
	//router.PUT("/", mainHandler)

	// err chan used for FCGI/HTTP listener goroutines and systemd socket-based activation goroutine
	errc := make(chan error)
	go func(errc chan error) {
		for err := range errc {
			log.Panic(err)
		}
	}(errc)

	// This will later be set to true if running as systemd socket-based activation, ensuring we are not defaulting to HTTP proxy in this case
	var UsingSystemd bool = false

	// If PROXY_TYPE environement variable is set, ensure it is either FCGI, HTTP or BOTH
	ProxyType := os.Getenv("PROXY_TYPE")
	if ProxyType != "" && strings.EqualFold(ProxyType, "FCGI") == false && strings.EqualFold(ProxyType, "HTTP") == false && strings.EqualFold(ProxyType, "BOTH") == false {
		log.Fatalf("Fatal: PROXY_TYPE environement variable must be either FCGI, HTTP or BOTH. Current is %v. Exiting.", ProxyType)
	}

	// init wg waitgroup var which will make main() wait until all goroutines (thread) have terminated
	var wg sync.WaitGroup

	// goroutine for systemd socket-basec activation
	// Don't scan for ProxyType as it's not necessary and won't be set when running behind systemd socket-based activation
	// This goroutine won't actually start if not run behind systemd socket-based activation
	SystemdListeners, err := activation.Listeners()
	if err != nil {
		log.Printf("Could not get systemd listeners: %v", err)
	}
	for _, SystemdListener := range SystemdListeners {
		log.Printf("Starting systemd socket-based activation thread")
		UsingSystemd = true
		wg.Add(1) // add 1 goroutine to wait for
		// systemd socket-based activation goroutine
		go func(errc chan error) {
			defer wg.Done() // defer marking the goroutine as done
			errc <- http.Serve(SystemdListener, router) // start systemd server with SystemdListener and router (gin) as handler
		}(errc)
	}

	// If PROXY_TYPE environement variable is not set AND we are not using systemd sockets-based activation, we default to HTTP proxy
	// This allows a default-proxy-mode operation but also prevents defaulting to this proxy type if ran for systemd but systemd goroutine crashed on startup
	if ProxyType == "" && UsingSystemd == false {
		log.Printf("PROXY_TYPE environement variable is not set, defaulting to HTTP proxy.")
		ProxyType = "HTTP"
	}

	// goroutine for FCGI
	if strings.EqualFold(ProxyType, "FCGI") || strings.EqualFold(ProxyType, "BOTH") { // strings.EqualFold() allows case insensitive comparison and is more efficient than strings.ToLower=strings.ToLower comparison (https://blog.digitalocean.com/how-to-efficiently-compare-strings-in-go/)
		fcgiPort := os.Getenv("FCGI_PORT")
		fcgiHost := os.Getenv("FCGI_HOST")
		if fcgiPort == "" { fcgiPort = "4000" }
		if fcgiHost == "" { fcgiHost = "127.0.0.1" }
		log.Printf("Starting FCGI thread with IP %v and port %v", fcgiHost, fcgiPort)
		// Create the FCGI listener
		fcgiListener, err := net.Listen("tcp", fcgiHost + ":" + fcgiPort)
		if err != nil {
			log.Panic(err)
		}
		defer fcgiListener.Close()
		wg.Add(1) // add 1 goroutine to wait for
		// FCGI goroutine
		go func(errc chan error) {
			defer wg.Done() // defer marking the goroutine as done
			errc <- fcgi.Serve(fcgiListener, router) // start FCGI server with fcgiListener and router (gin) as handler
		}(errc)
	}

	// goroutine for HTTP
	if strings.EqualFold(ProxyType, "HTTP") || strings.EqualFold(ProxyType, "BOTH") { // strings.EqualFold() allows case insensitive comparison and is more efficient than strings.ToLower=strings.ToLower comparison (https://blog.digitalocean.com/how-to-efficiently-compare-strings-in-go/)
		httpPort := os.Getenv("HTTP_PORT")
		httpHost := os.Getenv("HTTP_HOST")
		if httpPort == "" { httpPort = "8080" }
		log.Printf("Starting HTTP thread with IP %v and port %v", httpHost, httpPort)
		// Create the HTTP listener
		httpListener, err := net.Listen("tcp", httpHost + ":" + httpPort)
		if err != nil {
			log.Panic(err)
		}
		defer httpListener.Close()
		wg.Add(1) // add 1 goroutine to wait for
		// HTTP goroutine
		go func(errc chan error) {
			defer wg.Done() // defer marking the goroutine as done
			//errc <- http.Serve(httpListener, router) // start HTTP server with httpListener and router (gin) as handler
			// HTTP server configuration goes here (handler, read/write timeout, ...)
			httpServer := &http.Server{
				Handler: router,
			}
			httpServer.SetKeepAlivesEnabled(true) // enable tcp keepalive for HTTP server
			defer httpServer.Close()
			errc <- httpServer.Serve(httpListener) // start HTTP server with httpListener using httpServer configuration (uses router (gin) as handler)
		}(errc)
	}

	log.Printf("Waiting for connections")
	wg.Wait() // wait for all goroutine to have terminated
}
