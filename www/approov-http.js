/**********************************************************************************************
 * Project:     Approov
 * File:        approov-http.js
 * Original:    Created on 17 Jan 2018 by johanness
 *
 * Copyright(c) 2018 by CriticalBlue Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 **********************************************************************************************/

var cordova = require('cordova');

function handleMissingCallbacks(successFn, failFn) {
    if (Object.prototype.toString.call(successFn) !== '[object Function]') {
        throw new Error('approov-http: missing mandatory "onSuccess" callback function');
    }

    if (Object.prototype.toString.call(failFn) !== '[object Function]') {
        throw new Error('approov-http: missing mandatory "onFail" callback function');
    }
}

var approovHttp = {
    approovConfigure: function (config, success, failure) {
        handleMissingCallbacks(success, failure);
        config = config || {};

        return cordova.exec(success, failure, "CordovaApproovHttpPlugin", 'approovConfigure', [config]);
    }
}

module.exports = approovHttp;
