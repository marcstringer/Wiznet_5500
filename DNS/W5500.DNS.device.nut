// static VERSION = "1.0.0";

// MIT License
//
// Copyright 2017 Electric Imp
//
// SPDX-License-Identifier: MIT
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
// EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

// process id
// 2 bytes
const W5500_DNS_PRCID1 = 0x11;
const W5500_DNS_PRCID2 = 0x11;

// Flags
// The following bytes declare a message where opcode = standard, message not truncated
// 2 bytes
const W5500_DNS_FLAGS1 = 0x01;
const W5500_DNS_FLAGS2 = 0x00;

// Number of Questions
// 2 bytes
const W5500_DNS_NOFQ1 = 0x00;
const W5500_DNS_NOFQ2 = 0x01;
// Number of Answers not relevant to a query (always set to 0 in query)
// 2 bytes
const W5500_DNS_NOFA1 = 0x00;
const W5500_DNS_NOFA2 = 0X00;

// Number of Authority Resource Record count (always set to 0 in query)
// 2 bytes
const W5500_DNS_AURR1 = 0x00;
const W5500_DNS_AURR2 = 0x00;

// Number of additional resource records in the DNS message (always set to 0 in query)
const W5500_DNS_ADRR1 = 0x00;
const W5500_DNS_ADRR2 = 0x00;

// Question section
// Question type A which means return a IPv4 record
const W5500_DNS_QTYPE1 = 0x00;
const W5500_DNS_QTYPE2 = 0x01

// question class internet
const W5500_DNS_QCLASS1 = 0x00;
const W5500_DNS_QCLASS2 = 0x01;

// number of bytes needed for a number
const W5500_DNS_NUM_BYTES_INT = 1;

// expected packet response
// expected flags
const W5500_DNS_MSG_RCV = 0X81; // indicates response from the dns server is a response to a dns query

// DNS SERVER RESPONSE ERROR CODES
const W5500_DNS_MSG_NO_ERR = 0x80; // no errors received
const W5500_DNS_MSG_FRMAT_ERR = 0x81; // formatting error
const W5500_DNS_MSG_SRVR_ERR = 0x82; // server error
const W5500_DNS_MSG_DMAIN_NOT_EXIST_ERR = 0x83; // domain name does not exist
const W5500_DNS_MSG_QUERY_NOT_SUPPORTD = 0x84; // the query type is not supported by the dns server
const W5500_DNS_MSG_SERVER_REFUSED = 0x85; // server refused the request

// VALUES
const W5500_DNS_NAME1 = 0xc0; // initial name bytes
const W5500_DNS_NAME2 = 0x0c;
const W5500_DNS_NUM_DNS_SERVERS = 4; // number of dns servers
const W5500_DNS_PORT = 53; // port used for dns requests
const W5500_DNS_A = 1; // represents an A record type
const W5500_DNS_CNAME = 5; // represents a CNAME record type


// ERROR messages

const W5500_DNS_ERR_PRCID = "error: invalid process id received" ;
const W5500_DNS_ERR_IP = "error: incorrect ip address received";
const W5500_DNS_ERR_PORT = "Invalid Port";
const W5500_DNS_ERR_DNS_RSPNSE = "error: response from the dns was not a dns response packet";
const W5500_DNS_ERR_FRMAT = "error: message format sent is incorrect";
const W5500_DNS_ERR_DOMAIN = "error domain name referenced does not exist";
const W5500_DNS_ERR_UNEXP = "error: unexpected error";
const W5500_DNS_ERR_QS = "error: DNS response received incorrect number of questions";
const W5500_DNS_ERR_AUT_RESRCS = "error: unexpected number of authority resources";
const W5500_DNS_ERR_ADD_RSRCS = "error: unexpected number of additional resources";
const W5500_DNS_ERR_NOT_IPV4 = "error: answer is not ipv4";
const W5500_DNS_ERR_NOT_INET = "error: answer is not of the internet class";
const W5500_DNS_ERR_NO_NAME = "error : DNS Name not present";
const W5500_DNS_ERR_INVLID_RCORD = "error: invalid record type (only accept A or CNAME)";
// ==============================================================================
// CLASS: W5500.DNS
// ==============================================================================

class W5500.DNS {

    _hostName = null; // hostName which must be a string
    _wiz = null; // configured wiznet object
    _receivedData = null; // received data
    _hostNameLength = null; // length in bytes of the hostName packed
    _TTL = null; // time to to live of the IPv4 address
    _ipCount = 1; // dns server ip index
    _prcid1 = null; // process id
    _prcid2 = null;
    _retryCount = 0; // udp retry count
    _receivedDataFlag = false; // flag raised when data packet arrives
    _connection = null; // wiznet connection instance
    _debug = 0; // displays logs
    _waiting = null; // waiting for a response from the server
    // table of ip addresses for dns servers
    _dnsIpAddr = {
        "ip1": [8, 8, 8, 8],
        "ip2": [8, 8, 4, 4],
        "ip3": [208, 67, 222, 222],
        "ip4": [208, 67, 220, 220]
    }

    constructor(wiznet) {
        _wiz = wiznet;
    }

    /***************************************************************************
     *  generateProcessId
     *  Returns:
     *  Parameters:
     ***************************************************************************/
    // generates process ids for the dns request
    // the id is set to variable within the class
    function _generateProcessId() {
        local roll1 = ((1.0 * math.rand()) / RAND_MAX)*255;
        local roll2 = ((1.0 * math.rand()) / RAND_MAX)*255;
        //roll1 = roll1 * 255;
        //roll2 = roll2 * 255;
        _prcid1 = roll1.tointeger();
        _prcid2 = roll2.tointeger();
    }

    /***************************************************************************
     *  questionName
     *  Returns:
     *      arrayElements - an array of Elements that containing a hostName broken down
     *                      into the appropriate format for a dns request
     *  Parameters:
     *      hostName - a string representation of a hostName
     ***************************************************************************/
    // Converts the hostName into the required format for the dns query
    function _questionName(hostName) {
        local strI = 0; // string index
        local currChar = ""; // current character of the hostName
        local count = 0; // section count
        local strngSction = ""; // section of the hostName to be passed to the packet maker
        local arrayElements = []; // array to be made into a packet
        local idNum = 0; // number to so that the element can be identified in the array
        local totalLength = 0; // total length in bytes

        for (strI = 0; strI < hostName.len(); strI += 1) {

            currChar = hostName.slice(strI, strI + 1);

            // check if segment should be ending
            if (currChar == "." || strI == hostName.len() - 1) {

                // special case if last character in hostName
                // "." is usually discarded for last character however needs to be included in segment
                if (strI == hostName.len() - 1) {
                    count += 1;
                    strngSction += currChar;
                }

                local element = {} // element to be added to array
                    // add the segment length to the array
                element.k <- "QN" + idNum.tostring();
                element.s <- 1;
                element.v <- count;
                arrayElements.append(element);
                idNum += 1;

                element = {}
                    // add the string segment to the array
                element.k <- "QN" + idNum.tostring();
                element.s <- strngSction.len();
                element.v <- strngSction;
                arrayElements.append(element);
                idNum += 1;
                totalLength += (1 + strngSction.len());

                // adds a final element to the array indicating length of next segment is 0
                if (strI == hostName.len() - 1) {
                    element = {}
                        // add the segment
                    element.k <- "QN" + idNum.tostring();
                    element.s <- 1;
                    element.v <- 0;
                    arrayElements.append(element);
                    totalLength += 1;
                }

                // resets the segment counters
                count = 0;
                strngSction = "";
            }

            // if segment not ending increment count
            // add character to the string section
            else {
                count += 1;
                strngSction += currChar;
            }

        }
        _hostNameLength = totalLength;
        return arrayElements;
    }

    /***************************************************************************
     *  _arrayAssembly
     *  Returns:
     *      array - an array of Elements that will make up the packet to be sent
     *              to the dns server
     *  Parameters:
     *      hostNameArray - the formatted hostName to be sent to the dns
     ***************************************************************************/
    // assembles the array that will be made into a packet
    function _arrayAssembly(hostNameArray) {

        local array = [{ "k": "id1", "s": W5500_DNS_NUM_BYTES_INT, "v": _prcid1 },
            { "k": "id2", "s": W5500_DNS_NUM_BYTES_INT, "v": _prcid2 },
            { "k": "flags1", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_FLAGS1 },
            { "k": "flags2", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_FLAGS2 },
            { "k": "NOFQ1", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_NOFQ1 },
            { "k": "NOFQ2", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_NOFQ2 },
            { "k": "NOFA1", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_NOFA1 },
            { "k": "NOFA2", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_NOFA2 },
            { "k": "NAUR1", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_AURR1 },
            { "k": "NAUR2", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_AURR2 },
            { "k": "NADR1", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_ADRR1 },
            { "k": "NADR2", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_ADRR2 }
        ];

        array.extend(hostNameArray);
        array.extend([{ "k": "QTYP1", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_QTYPE1 },
            { "k": "QTYP2", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_QTYPE2 },
            { "k": "QCLS1", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_QCLASS1 },
            { "k": "QCLS2", "s": W5500_DNS_NUM_BYTES_INT, "v": W5500_DNS_QCLASS2 }
        ]);


        return array;

    }

    /***************************************************************************
     *  _makePacket
     *  Returns:
     *     _outputPacket - a blob consisting of the data to be sent to the dns
     *                      server
     *  Parameters:
     *      structure - an array of data to be sent to a dns server
     ***************************************************************************/
    // makes a packet (blob) which is transmittable
    function _makePacket(structure) {
        local _packetSize = 0;
        local _outputPacket = null;

        // Add up total size
        foreach (item in structure) {
            _packetSize += item.s;
        }
        _outputPacket = blob(_packetSize);
        // Write data into blob
        foreach (item in structure) {
            if (item.v != null) {
                switch (typeof(item.v)) {
                    case "string":
                        _outputPacket.writestring(item.v);
                        break;
                    case "integer":
                        _outputPacket.writen(item.v, 'b');
                        break;
                    case "blob":
                        _outputPacket.writeblob(item.v);
                        break;
                }
            } else {
                _outputPacket.seek(item.s, 'c');
            }
        }
        return _outputPacket;
    }

    /***************************************************************************
     *  _checkIP
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // check it was the right ip address that was sent to
    function _checkIP(packet) {

        local ipNum = "ip" + _ipCount.tostring();
        for (local i = 0; i < 4; i++) {
            if (packet.readn('b') != _dnsIpAddr[ipNum][i]) {
                throw W5500_DNS_ERR_IP;
            }
        }
    }

    /***************************************************************************
     *  _checkPort
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // check that packet was returned on the correct port
    function _checkPort(packet) {
        // discard an unimportant byte
        packet.seek(1, 'c');
        local port = packet.readn('b');
        if (port == W5500_DNS_PORT) {
            packet.seek(2, 'c');
        } else {
            throw W5500_DNS_ERR_PORT;
        }

    }

    /***************************************************************************
     *  _checkProcessID
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // check that the process id is the same one that we sent
    function _checkProcessID(packet) {
        local p1 = packet.readn('b');
        local p2 = packet.readn('b');
        if (_debug) {
            server.log ("return id packet " + p1 + p2 );
            server.log ("generated packet " + _prcid1  + _prcid2);
        }
        if ((p1 == _prcid1) && (p2 == _prcid2)) {} else {
            throw W5500_DNS_ERR_PRCID;
        }

    }

    /***************************************************************************
     *  _checkflags
     *  Returns:
     *  Parameters:
     *      packet -blob received from the dns server
     *      hostName -   a string containing a hostName address
     *      cb -    a callback function to be called once received packet is unpacked
     *              connection - the instance of the connection

     ***************************************************************************/
    // check the flags for a message received
    // check the flags for any errors sent by the server
    function _checkflags(packet, hostName, cb) {
        local flagsRec = packet.readn('b');
        local flagsErrors = packet.readn('b');

        if (flagsRec != W5500_DNS_MSG_RCV) {
            throw W5500_DNS_ERR_DNS_RSPNSE;
        }

        if (flagsErrors != W5500_DNS_MSG_NO_ERR) {
            if (flagsErrors == W5500_DNS_MSG_FRMAT_ERR) {
                throw W5500_DNS_ERR_FRMAT;
            } else if (flagsErrors == (W5500_DNS_MSG_SRVR_ERR || W5500_DNS_MSG_QUERY_NOT_SUPPORTD || W5500_DNS_MSG_SERVER_REFUSED)) {
                // retry with a different dns server
                _dnsServerChange(hostName, cb);
            } else if (flagsErrors == W5500_DNS_MSG_DMAIN_NOT_EXIST_ERR) {
                throw W5500_DNS_ERR_DOMAIN;
            } else {
                throw W5500_DNS_ERR_UNEXP;
            }
        }

    }

    /***************************************************************************
     *  _numberQs
     *  Returns:
     *      numberOfQuestions - number of question the dns server received
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Number of Questions that the the dns server has received
    function _numberQs(packet) {
        packet.seek(1, 'c');
        if (packet.readn('b') != 1) {
            throw W5500_DNS_ERR_QS;
        }
    }

    /***************************************************************************
     *  _numberAns
     *  Returns:
     *      numberOfAnswers - number of answers the dns server has provided
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Number of answers that the dns server has provided
    function _numberAns(packet) {
        packet.seek(1, 'c');
        local numberOfAnswers = packet.readn('b');
        return numberOfAnswers;
    }

    /***************************************************************************
     *  _checkAuthority
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Checks that the correct number of authority resources were received
    function _checkAuthority(packet) {
        if (packet.readn('w') != 0) {
            throw W5500_DNS_ERR_AUT_RESRCS;
        }

    }

    /***************************************************************************
     *  _checkAdditionalResources
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Checks that the correct number of additional resources were received
    function _checkAdditionalResources(packet) {
        if (packet.readn('w') != 0) {
            throw W5500_DNS_ERR_ADDRESRCS;
        }

    }

    /***************************************************************************
     *  _checkIPV4
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Checks that the dns server received to specify a IPv4 address
    function _checkIPV4(packet) {
        packet.seek(1, 'c');
        local byte = packet.readn('b');
        if (byte != 1) {
            throw W5500_DNS_ERR_NOT_IPV4;
        }
    }

    /***************************************************************************
     *  _checkInternet
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Checks that the dns server received to specified the internet class
    function _checkInternet(packet) {
        packet.seek(1, 'c');
        local byte = packet.readn('b');
        if (byte != 1) {
            throw W5500_DNS_ERR_NOT_INET;
        }
    }

    /***************************************************************************
     *  _checkName
     *  Returns:
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Checks that the Name indicator is in the correct place
    function _checkName(packet) {
        local p1 = packet.readn('b');
        local p2 = packet.readn('b');
        if ((p1 != W5500_DNS_NAME1) && (p2 != W5500_DNS_NAME2)) {
            throw W5500_DNS_ERR_NO_NAME;
        }

    }

    /***************************************************************************
     *  _checkRecord
     *  Returns:
     *      record - the type of answer the dns server has sent
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Checks what record the dns server has responded with
    function _checkRecord(packet) {
        packet.seek(1, 'c');
        local record = packet.readn('b');
        return record
    }

    /***************************************************************************
     *  _getTTL
     *  Returns:
     *      ttl - the time to live on the provided ip address i.e how long before
     *            you need to renew it
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Reads the ttl from the received packet
    function _getTTL(packet) {
        local ttl = packet.readn('i');
        return ttl;
    }

    /***************************************************************************
     *  _lengthAnswer
     *  Returns:
     *      length - the  number of bytes that the are used to represent the ip
     *               address
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Reads the number of bytes that are used to write the ip address
    function _lengthAnswer(packet) {
        packet.seek(1, 'c');
        local length = packet.readn('b');
        return length
    }

    /***************************************************************************
     *  _ipAddress
     *  Returns:
     *      array - an array consisting of 4 elements that make up an ip address
     *  Parameters:
     *      packet - blob received from the dns server
     ***************************************************************************/
    // Reads the ip address returned from the dns server
    function _ipAddress(packet, answerLength) {
        local array = [];
        for (local i = 0; i < answerLength; i++) {
            array.append(packet.readn('b'));
        }
        return array;
    }

    /***************************************************************************
     *  _parsePacket
     *  Returns:
     *      ip - an array which contains the ip address
     *  Parameters:
     *      packet - blob received from the dns server
     *      hostNameR - hostName in string form
     *      cbR - to be called after ip address is returned
     ***************************************************************************/
    // breaks up the received packet checking to ensure its validity and finally
    // finding the ip address
    function _parsePacket(packet, hostNameR, cbR) {
        local element = {}; // element to be added to the array
        local arrayIP = []; // array of ip addresses
        local idNum = 0; // id number used for the key of the returned ip address

        // blob pointer at start of blob
        packet.seek(0, 'b');

        // perform various data checks break up data
        // check the message header
        _checkIP(packet);
        _checkPort(packet);
        _checkProcessID(packet);
        _checkflags(packet, hostNameR, cbR);
        _numberQs(packet);
        local numAns = _numberAns(packet);
        _checkAuthority(packet);
        _checkAdditionalResources(packet);
        local hostName = packet.readstring(_hostNameLength)
        _checkIPV4(packet);
        _checkInternet(packet);

        // unpack the answer section
        _checkName(packet);
        local initialRecord = _checkRecord(packet);

        // if it is a type A answer
        if (initialRecord == 1) {
            _checkInternet(packet);
            _TTL = _getTTL(packet);
            local answerLength = _lengthAnswer(packet);
            local ip = _ipAddress(packet, answerLength);
            element = {}
            element.k <- "IP" + idNum.tostring();
            element.v <- ip;
            arrayIP.append(element);
            return arrayIP;
        }

        // if it is a CNAME answer
        else if (initialRecord == W5500_DNS_CNAME) {
            for (local cnt_i = 0; cnt_i < numAns; cnt_i++) {
                // check name and record on subsequent loops
                if (cnt_i > 0) {
                    packet.seek(2, 'c');
                    local currentRecord = _checkRecord(packet);
                }
                _checkInternet(packet);
                _TTL = _getTTL(packet);
                local answerLength = _lengthAnswer(packet);
                // if its a A record ip address we add it to the table of ip addresses
                if (currentRecord == W5500_DNS_A) {
                    local ip = _ipAddress(packet, answerLength);
                    element = {}
                    element.k <- "IP" + idNum.tostring();
                    element.v <- ip;
                    arrayIP.append(element);
                    idNum += 1;
                }
                // if its not an A record we discard it
                else {
                    packet.seek(answerLength, 'c');
                }
            }
            return arrayIP;
        } else {
            throw W5500_DNS_ERR_INVLID_RCORD;
        }

    }

    /***************************************************************************
     *  _backOffHandler
     *  Returns:
     *  Parameters:
     *       hostName - a string containing a hostName address
     *       cb - a callback function to be called once received packet is unpacked
     *       connection - the instance of the connection
     ***************************************************************************/
    // handles re query back off if a server is non responsive
    function _backOffHandler(hostName, connection, cb) {

        local timeToWait = math.pow(2, _retryCount + 1);
        if (_debug) { server.log("waiting for..." + timeToWait) };
        _waiting = imp.wakeup(timeToWait, function() {
            if (_receivedDataFlag == false) {
                // may retry dns server several times
                if (_retryCount >= 2) {
                    _dnsServerChange(hostName, cb);
                    if (_debug) {server.log("error: failed to receive response from a dns server")};

                } else {
                    connection.close();
                    _connection = null;
                    _retryCount += 1;
                    dnsResolve(hostName, cb);

                }
            }
        }.bindenv(this));

    }

    /***************************************************************************
     *  _dnsServerChange
     *  Returns:
     *  Parameters:
     *      hostName - a string containing a hostName adress
     *      cb - a callback function to be called once received packet is unpacked
     ***************************************************************************/
     // switches between dns servers by incrementing _ipCount when dnsResolve
     // chooses a the next dns ip adress from the array
     function _dnsServerChange (hostName, cb) {
         _ipCount += 1; // increment to go to next dns server
         _retryCount = 0; // reset retry count for a fresh approach for next dns server
         _connection.close();
         _connection = null ;
         dnsResolve(hostName, cb);
     }





    /***************************************************************************
     *  dnsResolve
     *  Returns:
     *  Parameters:
     *      hostName - a string containing a hostName address
     *      cb - a callback function to be called once received packet is unpacked
     ***************************************************************************/
    // Transmit the packet to a dns server and receives the response
    function dnsResolve(hostName, cb) {

        // check if have run through every dns server to attempt to retrieve ip
        if (_ipCount > W5500_DNS_NUM_DNS_SERVERS) {
            throw "Have run through all listed dns servers unable to retrieve ip";
        }
        _generateProcessId();
        local hostNameArray = _questionName(hostName);
        local packet = _makePacket(_arrayAssembly(hostNameArray));
        if (_debug) { server.log(packet) };
        local ipNum = "ip" + _ipCount.tostring();
        local destIP = _dnsIpAddr[ipNum];
        local destPort = W5500_DNS_PORT;
        local IPArray;

        local receiveCb = function(err, data) {
            _receivedDataFlag = true;
            imp.cancelwakeup(_waiting);
            if (err) {
                _connection.close();
                _connection = null;
                return cb(err, null) }
            else {
                if (_debug) {
                    server.log("data is received");
                    server.log(data);
                }
                IPArray = _parsePacket(data, hostName, cb);
                _connection.close();
                _connection = null;
                cb(null, IPArray);
            }

        }.bindenv(this);

        _wiz.openConnection(destIP, destPort, W5500_SOCKET_MODE_UDP, function(err, connection) {

            if (err) {
                server.error("Connection failed " + err);
                _ipCount += 1;
                dnsResolve(hostName, cb);
            };
            else {
                _connection = connection;
                if (_debug) { server.log("connection est..") };
                _backOffHandler(hostName, connection, cb);
                // initialise callback that is called when data is received
                connection.onReceive(receiveCb);
                // transmit the dns packet
                connection.transmit(packet, function(err) {
                    if (err) {
                        server.error("Send failed, closing: " + err);
                        connection.close();
                        _connection = null;
                    }
                }.bindenv(this));

            }


        }.bindenv(this));

    }

}
