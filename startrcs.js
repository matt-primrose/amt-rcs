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
* @description Simple script to instantiate and start the RCS service
* @author Matt Primrose
* @version v0.1.0
* @dependencies
*/

'use strict'
const fs = require('fs');
var rcs = require('./amt-rcs');
var config = './rcs-config.json';
function startrcs() {
    var rcsconfig = fs.readFile(config, 'utf8', function (err, file) {
        var RS = rcs(JSON.parse(file.trim()));
        RS.start();
    });
}

startrcs();