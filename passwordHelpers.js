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

let passwordHelpers = new Object();

/**
 * @description Checks the proposed AMT password against AMT password requirements
 * @param {string} password Password string to test
 * @returns {boolean} Returns true if password meets AMT password requirements
 */
passwordHelpers.passwordCheck = function(password){
    let pass = new Boolean();
    let len = 8;
    let matches = new Array();
    matches.push(/\W|_/g);
    matches.push(/[A-Z]/g);
    matches.push(/[0-9]/g);
    matches.push(/[a-z]/g);
    let n = 0;
    for (let i = 0; i < matches.length; i++){
        if (new RegExp(matches[i]).test(password)){
            n++;
        }
    }
    if (password.length < len || n < 4){
        pass = false;
    } else {
        pass = true;
    }
    return pass;
};

/**
 * @description Generates a random password out of a given set of characters and of a given length
 * @param {string} validChars String containing all valid password characters
 * @param {number} length Length of desired password 
 * @returns {string} Returns random password string
 */
passwordHelpers.generateRandomPassword = function(length){
    if ((length < 8) || (length > 32)){ return {'errorText': 'Invalid password length specified.'}; }
    let password = '';
    let validChars = "abcdefghijklmnopqrstuvwxyz";
    let validNums = "0123456789";
    let validSpec = "!@#$%^&*()_-+=?.>,<";
    let numLen = Math.floor(Math.random() * length/3) + 1;
    let specLen = Math.floor(Math.random() * length/3) + 1;
    let charLen = length-numLen-specLen;
    for (let x = 0; x < charLen; x++){
        let upper = Math.random() >= 0.5;
        if (upper == true){ password += validChars.charAt(Math.floor(Math.random() * validChars.length)).toUpperCase(); }
        else { password += validChars.charAt(Math.floor(Math.random() * validChars.length)); }
    }
    for (let x = 0; x < specLen; x++){
        password += validSpec.charAt(Math.floor(Math.random() * validSpec.length));
    }
    for (let x = 0; x < numLen; x++){
        password += validNums.charAt(Math.floor(Math.random() * validNums.length));
        password = password.split('').sort(function(){ return 0.5 - Math.random() }).join('');
    }
    if (!passwordHelpers.passwordCheck(password)) { passwordHelpers.generateRandomPassword(length); }
    return password;
};

/**
 * @description Checks the AMT passwords in the rcsConfig and rejects any configurations that don't meet AMT password standards
 * @param {array} list List of AMT configurations
 */
passwordHelpers.validateAMTPasswords = function(list, callback){
    for(let x = 0; x < list.length; x++){
        if (list[x].GenerateRandomPassword === false){
            if(!passwordHelpers.passwordCheck(list[x].AMTPassword)){
                callback({'errorText': "Detected bad AMT password for profile: " + list[x].ProfileName + "./n/rRemoving " + list[x].ProfileName + " profile from list of available AMT profiles."});
                list.splice(x, 1);
                passwordHelpers.validateAMTPasswords(list);
            }
        } else {
            if((list[x].RandomPasswordLength > 32) || (list[x].RandomPasswordLength < 8)){
                callback({'errorText': "Detected bad AMT password length for profile: " + list[x].ProfileName + "./n/rRemoving " + list[x].ProfileName + " profile from list of available AMT profiles."});
                list.splice(x, 1);
                passwordHelpers.validateAMTPasswords(list);
            }
        }
    }
    return list;
}

module.exports = passwordHelpers;