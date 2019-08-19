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
const passwordHelpers = require('../passwordHelpers');
test('Returns true if password meets criteria', () =>{
    expect(passwordHelpers.passwordCheck('P@ssw0rd')).toBe(true);
});
test('Returns false if password does not meet criteria', () =>{
    expect(passwordHelpers.passwordCheck('password')).toBe(false);
});
test('Returns a random password that passes the password checker', ()=>{
    let length = 8;
    let password = passwordHelpers.generateRandomPassword(length);
    console.log(password);
    expect(passwordHelpers.passwordCheck(password)).toBe(true);
});
test('Returns an error if password length is too short', ()=>{
    let length = 4;
    let cbMessage = passwordHelpers.generateRandomPassword(length)
    expect(cbMessage.errorText).toBe("Invalid password length specified.");
});
test('Returns an error if password length is too long', ()=>{
    let length = 33;
    let cbMessage = passwordHelpers.generateRandomPassword(length)
    expect(cbMessage.errorText).toBe("Invalid password length specified.");
});
test('Returns error message if a bad AMT password is detected', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "password","GenerateRandomPassword": false,"RandomPasswordLength": 8,"Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    passwordHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns error message if random AMT password length is too short', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 7,"Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    passwordHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password length for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns error message if random AMT password length is too long', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 33,"Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    passwordHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password length for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns list without bad profile', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 33,"Activation": "ccmactivate","ConfigurationScript": null}];
    list = passwordHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(0);
});
test('Returns list with good profile - Set Password', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "P@ssw0rd","GenerateRandomPassword": false,"RandomPasswordLength": 33,"Activation": "ccmactivate","ConfigurationScript": null}];
    list = passwordHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(1);
});
test('Returns list with good profile - Random Password', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "password","GenerateRandomPassword": true,"RandomPasswordLength": 10,"Activation": "ccmactivate","ConfigurationScript": null}];
    list = passwordHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(1);
});