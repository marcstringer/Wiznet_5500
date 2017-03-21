# Wiznet 5500 DNS

This library class enables Domain Name Service (*DNS*) functionality for the Wiznet W5500 chip [W5500](http://wizwiki.net/wiki/lib/exe/fetch.php?media=products:w5500:w5500_ds_v106e_141230.pdf). It also requires the Wiznet W5500 driver.  

**To add this code to your project, add `#require W5500.DNS.device.nut ` after `#require "W5500.device.nut:1.0.0"` to the top of your device code.**

## Class W5500.DNS

### Constructor: W5500.DHCP(*wiz*)
Instantiates a new W5500.DNS object and passes in a configured Wiznet object
enabling the W5500.DNS to utilise W5500 functionality.

## Class Methods

### dnsResolve(*url, cb*)
This function performs a dns request for the given url. The returned ip address is passed into the callback.

| Key | Data Type |Required | Default Value |Description |
|----|------------|---------|--------------|------------|
|url|String|Yes|N/A|a url address i.e "www.google.com"|
|cb|function|Yes|N/A| A callback function that is passed an error message or a table of received ip addresses|

#### Example Code:
```squirrel
    local url = "www.google.com" ;
    // where wiz is configured W5500 object (see W5500.device.nut for an example)
    query <- W5500.DNS(wiz);
    query.dnsResolve(url);
```

#### Callback Arguments
|Key |Data Type|Description|
|-----|----|----|
|error|string|An error message if there was a issue receiving the data or null if it was successful|
|data|table|received IPV4 addresses stored in arrays within a table|
