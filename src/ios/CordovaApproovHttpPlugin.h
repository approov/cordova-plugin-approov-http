/**********************************************************************************************
 * Project:     Approov
 * File:        CordovaApproovHttpPlugin.h
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

#import <Foundation/Foundation.h>

#import <Cordova/CDVPlugin.h>

@interface CordovaApproovHttpPlugin : CDVPlugin

/* Configure the Approov plugin */
- (void)approovConfigure:(CDVInvokedUrlCommand*)command;

@end
