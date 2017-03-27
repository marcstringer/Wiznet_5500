#include "../../W5500.device.nut"
#include "../W5500.DNS.device.nut"

// Initialise SPI port
interruptPin <- hardware.pinXC;
resetPin <- hardware.pinXA;
spiSpeed <- 1000;
spi <- hardware.spi0;
spi.configure(CLOCK_IDLE_LOW | MSB_FIRST | USE_CS_L, spiSpeed);

// Initialise Wiznet
wiz <- W5500(interruptPin, spi, null, resetPin);

function dnsCB() {
    local ipAdresses = null;
    server.log("hello world");
    wiz.configureNetworkSettings("192.168.201.37", "255.255.255.0", "192.168.201.1");
    // Initialise dns requires a configure wiznet object

    service <- W5500.DNS(wiz);
    service.dnsResolve("www.facebook.com", function (err, data) {
        if (err) {
            throw err;
        }
        else {
            // display all returned ip addresses
            for (local i =0; i < data.len(); i++ ) {
                server.log(data[i]);
            }
        }
    });
}

wiz.onReady(dnsCB);
