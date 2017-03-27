// echo server address and port
const SOURCE_IP = "192.168.201.37";
const SUBNET_MASK = "255.255.255.0";
const GATEWAY_IP = "192.168.201.1";


const URL_CLASS_A = "www.google.com";
const URL_CLASS_CNAME = "www.facebook.com";
const HOST_NAME_NO_DNS = "www.facebook.com.www.facebook.com"
// server that does not respond to a dns request
const SERVER_NO_RESPONSE  = "2.2.2.2";

class DeviceTestCase extends ImpTestCase {

    _wiz = null;
    _resetPin = hardware.pinXA;
    _interruptPin = hardware.pinXC;
    _spiSpeed = 1000;
    _spi = hardware.spi0;
    _dns = null;
    // setup function needed to run others. Instantiates the wiznet driver.
    function setUp() {

        _spi.configure(CLOCK_IDLE_LOW | MSB_FIRST | USE_CS_L, _spiSpeed);

        // Initialise Wiznet
        _wiz = W5500(_interruptPin, _spi, null, _resetPin);

        // will not finish until the onReady event is called
        return Promise(function(resolve, reject) {
            _wiz.onReady(function() {
                _dns = W5500.DNS(_wiz);
                resolve();
            }.bindenv(this));

            imp.wakeup(5, function() {
                reject("timeout...");
            }.bindenv(this));

        }.bindenv(this));
    }
    // /////////////////////////////////////////////////////////////////////////
    //  Static Cases
    // /////////////////////////////////////////////////////////////////////////

    // asserting that the function QuestionName correctly turns a url string
    // into the required format of a url for a dns request
    function testQuestionName() {
        // note this is specific to the URL_STRING
        // follow
        local expectedArray = [
            { "k": "QN0", "s": 1, "v": 3 },
            { "k": "QN1", "s": 3, "v": "www" },
            { "k": "QN2", "s": 1, "v": 6 },
            { "k": "QN3", "s": 6, "v": "google" },
            { "k": "QN4", "s": 1, "v": 3 },
            { "k": "QN5", "s": 3, "v": "com" },
            { "k": "QN6", "s": 1, "v": 0 }
        ]
        local actualArray = _dns._questionName(URL_CLASS_A);
        this.assertDeepEqual(expectedArray, actualArray);
    }

    // make a number of fake pack then check that the functions in
    // parsePacket perform as expected
    function testIPchecker() {
        _dns._ipCount = 1;
        local check;
        local testPass = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": 8 },
            { "k": "ip2", "s": 1, "v": 8 },
            { "k": "ip3", "s": 1, "v": 4 },
            { "k": "ip4", "s": 1, "v": 4 },
        ]);
        local testFail = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": 8 },
            { "k": "ip2", "s": 1, "v": 8 },
            { "k": "ip3", "s": 1, "v": 8 },
            { "k": "ip4", "s": 1, "v": 4 },
        ]);

        // test a pass case

        testPass.seek(0, 'b');
        check = _dns._checkIP(testPass);

        this.assertTrue(check == null, check);

        // test a failing case
        testFail.seek(0, 'b');
        check = _dns._checkIP(testFail);
        this.assertTrue(check == W5500_DNS_ERR_IP, check);


    }

    function testPort() {
        local check;
        local testPass = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": 0 },
            { "k": "ip2", "s": 1, "v": 53 },
            { "k": "ip3", "s": 1, "v": 1 },
            { "k": "ip4", "s": 1, "v": 1 },
        ]);
        local testFail = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": 8 },
            { "k": "ip2", "s": 1, "v": 12 },
            { "k": "ip3", "s": 1, "v": 1 },
            { "k": "ip4", "s": 1, "v": 1 },
        ]);
        // pass case
        testPass.seek(0, 'b');
        check = _dns._checkPort(testPass);
        this.assertTrue(check == null, check);

        // fail case
        testFail.seek(0, 'b');
        check = _dns._checkPort(testFail);
        this.assertTrue(check == W5500_DNS_ERR_PORT, check);
    }

    function testProcessId() {
        local check;
        _dns._generateProcessId();

        local testPass = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": _dns._prcid1 },
            { "k": "ip2", "s": 1, "v": _dns._prcid2 },
        ]);

        // very small chance accidentally passes
        local testFail = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": 1 },
            { "k": "ip2", "s": 1, "v": 1 },
        ]);
        // passing case
        testPass.seek(0, 'b');
        check = _dns._checkProcessID(testPass);
        this.assertTrue(check == null, check);
        // failing case
        testFail.seek(0, 'b');
        check = _dns._checkProcessID(testFail);
        this.assertTrue(check == W5500_DNS_ERR_PRCID, check);

    }

    function testFlags() {
        local check;
        local url = "nothing";
        local cb = "nothing";
        local testNotResponse = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": W5500_DNS_MSG_RCV + 1 },
            { "k": "ip1", "s": 1, "v": W5500_DNS_MSG_RCV },
        ]);
        local testFormat = _dns._makePacket([
            { "k": "ip1", "s": 1, "v": W5500_DNS_MSG_RCV },
            { "k": "ip1", "s": 1, "v": W5500_DNS_MSG_FRMAT_ERR }
        ]);

        testNotResponse.seek(0, 'b');
        check = _dns._checkflags(testNotResponse, url, cb);
        this.assertTrue(check == W5500_DNS_ERR_DNS_RSPNSE, "first "+ check);

        testFormat.seek(0, 'b');
        check = _dns._checkflags(testFormat, url, cb);
        this.assertTrue(check == W5500_DNS_ERR_FRMAT, "second "+ check);

    }



    // ///////////////////////////////////////////////////////////////////////////
    //  Live Cases
    // ///////////////////////////////////////////////////////////////////////////
    // these cases require a connection to a dns server and a server which is
    // connectable to but does not reply with a dns response packet

    // checks for both a timeout to an unresponsive dns server
    // moves to the next server
    // tests a record returns an ip address
    function testTimeout() {
        _wiz.configureNetworkSettings(SOURCE_IP, SUBNET_MASK, GATEWAY_IP);
        local dns = W5500.DNS(_wiz);
        dns._dnsIpAddr = [
            SERVER_NO_RESPONSE,
            "8.8.4.4",
            "208.67.222.222",
            "208.67.220.220"]

        return Promise(function(resolve, reject) {
            dns.dnsResolve(URL_CLASS_A, function(err, data) {
                // first ip address failed moved to the next 1
                this.assertTrue(dns._ipCount == 1, "ipcoutn is "+ dns._ipCount);
                // check that there is an ip address entered
                for (local i = 0; i < 4; i++) {
                    this.assertTrue(data[0].v[i] != null);
                }
                resolve();
            }.bindenv(this));
        }.bindenv(this));

    }

    // tests that a cname record provides a solution
    function testCNAME() {
        _wiz.configureNetworkSettings(SOURCE_IP, SUBNET_MASK, GATEWAY_IP);
        local dns = W5500.DNS(_wiz);
        return Promise(function(resolve, reject) {
            dns.dnsResolve(URL_CLASS_CNAME, function(err, data) {

                // check that connected to first dns server
                this.assertTrue(dns._ipCount == 0);
                // check that there is an ip address entered
                for (local i = 0; i < data.len(); i++) {
                    this.assertTrue(data[i].v != null);
                }

                resolve();
            }.bindenv(this));
        }.bindenv(this));

    }

    // test for a domain that does not resolve
    function testDomainNotExist () {
        _wiz.configureNetworkSettings(SOURCE_IP, SUBNET_MASK, GATEWAY_IP);
        local dns = W5500.DNS(_wiz);
        return Promise(function(resolve, reject) {
            dns.dnsResolve(HOST_NAME_NO_DNS, function(err, data) {
                this.assertTrue(err == W5500_DNS_ERR_DOMAIN, err);
                resolve();
            }.bindenv(this));
        }.bindenv(this));



    }












}
