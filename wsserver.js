/*
Copyright 2019 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
* @fileoverview Simple WebSocket Server
* @author Matt Primrose
* @version v0.1.0
*/

"use strict";
const http = require('https');
const WebSocket = require('ws');
const fs = require('fs');

/**
 * @description Creates the websocket server object
 * @param {number} port Port used for websocket communication
 * @param {boolean} tls Flag for enabling TLS
 * @param {string} wsscert location of TLS certificate
 * @param {string} wsscertkey private key of TLS certificate
 * @param {function} connectionHandler Callback function to calling library
 * @returns {object} Returns the websocket server object to the calling library
 */
function WebSocketServer(port, tls, wsscert, wsscertkey, connectionHandler) {   
    var obj = new Object();
    obj.port = port;
    obj.clients = [];
    obj.tls = tls;
    if (obj.tls == true) {
        try {
            var privateKey = fs.readFileSync(wsscertkey, 'utf8');
            var certificate = fs.readFileSync(wsscert, 'utf8');
        } catch (e) {
            console.log('TLS certificate not found.');
            process.exit(1);
        }
        var credentials = { key: privateKey, cert: certificate };
        obj.httpsServer = https.createServer(credentials);
        httpsServer.listen(obj.port);
        obj.wsServer = new WebSocket.Server({
            server: httpsServer
        });
    } else {
        obj.wsServer = new WebSocket.Server({ port: obj.port });
    }
    obj.wsServer.on('connection', (connection) => {
        // we need to know client index to remove them on 'close' event
        var index = obj.clients.push(connection) - 1;
        console.log((new Date()) + ' Connection accepted.');
        // message received
        connection.on('message', function (message) {
            obj.eventHandler('message', message, index);
        });
        // error received
        connection.on('error', function (event) { obj.eventHandler('error', event); });
        // client disconnected
        connection.on('close', function (connection) {
            obj.eventHandler('close', { "status": "ok", "event": "close", "data": "AMT Device " + index + " disconnected." }, index);
            // remove client from the list of connected clients
            obj.clients.splice(index, 1);
        });
    });
    obj.sendMessage = function (index, message) { obj.clients[index].send(JSON.stringify(message)); };
    obj.eventHandler = function (type, message, index) { connectionHandler(type, message, index); };
    return obj;
}
module.exports = WebSocketServer;