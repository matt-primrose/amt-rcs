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

/**
* @module wsserver
*/

/*
* @fileoverview Simple WebSocket Server
* @author Matt Primrose
* @version v0.1.0
*/

"use strict";
const WebSocket = require('ws');
const fs = require('fs');

/**
 * @constructor WebSocketServer
 * @description Creates the websocket server object
 * @param {number} port Port used for websocket communication
 * @param {boolean} tls Flag for enabling TLS
 * @param {string} wsscert location of TLS certificate
 * @param {string} wsscertkey private key of TLS certificate
 * @param {function} connectionHandler Callback function to calling library
 * @returns {object} Returns the websocket server object to the calling library
 */
function WebSocketServer(port, tls, wsscert, wsscertkey, connectionHandler, consoleLog) {   
    let obj = new Object();
    obj.port = port;
    obj.clients = [];
    obj.tls = tls;
    if (obj.tls == true) {
        try {
            let privateKey = fs.readFileSync(wsscertkey, 'utf8');
            let certificate = fs.readFileSync(wsscert, 'utf8');
        } catch (e) {
            if (consoleLog !== null) { consoleLog('TLS certificate not found.'); }
            else { console.log('TLS certificate not found.'); }
            process.exit(1);
        }
        let credentials = { key: privateKey, cert: certificate };
        obj.httpsServer = https.createServer(credentials);
        httpsServer.listen(obj.port);
        obj.wsServer = new WebSocket.Server({
            server: httpsServer
        });
    } else {
        obj.wsServer = new WebSocket.Server({ port: obj.port });
    }
    /**
    * @fires WebSocketServer#on
    * @description Handles messages coming in over the web socket
    */
    obj.wsServer.on('connection', (connection) => {
        // we need to know client index to remove them on 'close' event
        //let index = obj.clients.push(connection) - 1;
        if (consoleLog !== null) { consoleLog('Connection accepted.'); }
        else { console.log((new Date()) + ' Connection accepted.'); }
        /**
        * message received
        *
        * @event WebSocketServer#on
        * @type {object}
        * @property {string} message - fired when a message is received from client
        */
        connection.on('message', function (message) {
            obj.eventHandler('message', message, connection);
        });
        /**
        * error received
        *
        * @event WebSocketServer#on
        * @type {object}
        * @property {string} error - fired when a websocket error is received
        */
        connection.on('error', function (event) { obj.eventHandler('error', event, connection); });
        /**
        * client disconnected
        *
        * @event WebSocketServer#on
        * @type {object}
        * @property {string} close - fired when the websocket closes
        */
        connection.on('close', function (connection) {
            obj.eventHandler('close', { "status": "ok", "event": "close", "data": "AMT Device disconnected." }, connection);
            // remove client from the list of connected clients
            //obj.clients.splice(index, 1);
        });
    });
    /**
    * @external sendMessage
    * @description sends a message to the connected client
    * @param {Number} index Index of the connected client
    * @param {JSON} message Message in JSON format to be sent to client
    */
    obj.sendMessage = function (connection, message) { connection.send(message); };
    /**
    * @external eventHandler
    * @description forwards a message from the connected client to the backend service
    * @param {String} type Type of message being sent defined by websocket (message, error, close)
    * @param {String} message Message to be forwarded to backend service
    * @param {Number} index The index reference of the connected client
    */
    obj.eventHandler = function (type, message, connection) { connectionHandler(type, message, connection); };
    return obj;
}
module.exports = WebSocketServer;