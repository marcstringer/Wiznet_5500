# Wiznet 5500 DNS

This library class enables Domain Name Service (*DNS*) functionality for the Wiznet W5500 chip [W5500](http://wizwiki.net/wiki/lib/exe/fetch.php?media=products:w5500:w5500_ds_v106e_141230.pdf). It also requires the Wiznet W5500 driver.  

**To add this code to your project, add `#require W5500.DNS.device.nut ` after `#require "W5500.device.nut:1.0.0"` to the top of your device code.**

## Class W5500.DNS

### Constructor: W5500.DHCP(*wiz*)
Instantiates a new W5500.DNS object and passes in a configured Wiznet object
enabling the W5500.DNS to utilise W5500 functionality.

## Class Methods

### dnsResolve(*hostname, cb*)
This function performs a dns request for the given hostname Returning IPV4 addresses. The returned ip addresses are passed into the callback.The IPV4 addresses are stored as strings within an array.  

| Key | Data Type |Required | Default Value |Description |
|----|------------|---------|--------------|------------|
|hostname|String|Yes|N/A|a hostname i.e "www.google.com"|
|cb|function|Yes|N/A| A callback function that is passed an error message or a table of received ip addresses|


#### Callback Arguments
|Key |Data Type|Description|
|-----|----|----|
|error|string|An error message if there was a problem or null if successful.|
|data|array|An array with a table per received IPV4 address. Within the table is a key value pair: data[i].k A key indicating the i^th ip address in the array which is a string. data[i].v the value of the i^th received IPV4 address which is a string |

#### Example Code:
```squirrel
    local hostname = "www.google.com" ;
    // where wiz is configured W5500 object (see W5500.device.nut for an example)
    query <- W5500.DNS(wiz);
    query.dnsResolve(hostname, function(error, data) {
            if (error) {
                throw error;
            }
            else {
                // retrieve the first returned ip address
                local ip = data[0].v ;
            }
    });
```
### inputIpAddresses(*array*)
This function is used to input the dns servers ip addresses that you want the dns request to go to.

| Key | Data Type |Required | Default Value |Description |
|----|------------|---------|--------------|------------|
|hostname|array|Yes|N/A|an array of ip address strings e.g ["8.8.8.8", "8.8.4.4"] which are the ip addresses of google's public DNS servers |

#### Example Code:
```squirrel
    local hostname = "www.google.com" ;
    // where wiz is configured W5500 object (see W5500.device.nut for an example)
    query <- W5500.DNS(wiz);
    query.inputIpAddresses(["8.8.8.8", "8.8.4.4"]);

```
