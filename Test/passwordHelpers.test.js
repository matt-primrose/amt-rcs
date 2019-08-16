const passwordHelpers = require('../passwordHelpers');
test('Returns true if password meets criteria', () =>{
    expect(passwordHelpers.passwordCheck('P@ssw0rd')).toBe(true);
});
test('Returns false if password does not meet criteria', () =>{
    expect(passwordHelpers.passwordCheck('password')).toBe(false);
});
test('Returns a random password 8 characters long', ()=>{
    let length = 8;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&?*";
    let password = passwordHelpers.generateRandomPassword(characters, length);
    expect(password.length).toBe(8);
});
test('Returns a password with only "A" characters', ()=>{
    let length = 8;
    let characters = "A";
    let password = passwordHelpers.generateRandomPassword(characters, length);
    expect(password).toBe("AAAAAAAA");
});
test('Returns a random password 50 times', ()=>{
    let length = 8;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<";
    let i = 0;
    let spy = jest.spyOn(passwordHelpers, 'generateRandomPassword');
    while (i < 50){
        expect(passwordHelpers.generateRandomPassword(characters, length).length).toBe(8);
        i++;
    }
    expect(spy).toHaveBeenCalledTimes(50);
});
test('Returns an error if no password characters are passed in', ()=>{
    let length = 8;
    let characters = "";
    let cbMessage = "";
    passwordHelpers.generateRandomPassword(characters, length, function(message){
        cbMessage = message.errorText
    });
    expect(cbMessage).toBe("Not enough valid characters to create random password.");
});
test('Returns an error if password length is too short', ()=>{
    let length = 4;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<";
    let cbMessage = "";
    passwordHelpers.generateRandomPassword(characters, length, function(message){
        cbMessage = message.errorText
    });
    expect(cbMessage).toBe("Invalid password length specified.");
});
test('Returns an error if password length is too long', ()=>{
    let length = 33;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<";
    let cbMessage = "";
    passwordHelpers.generateRandomPassword(characters, length, function(message){
        cbMessage = message.errorText
    });
    expect(cbMessage).toBe("Invalid password length specified.");
});
test('Returns error message if a bad AMT password is detected', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "password","GenerateRandomPassword": false,"RandomPasswordLength": 8,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    passwordHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns error message if random AMT password length is too short', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 7,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    passwordHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password length for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns error message if random AMT password length is too long', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 33,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    passwordHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password length for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns list without bad profile', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 33,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    list = passwordHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(0);
});
test('Returns list with good profile - Set Password', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "P@ssw0rd","GenerateRandomPassword": false,"RandomPasswordLength": 33,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    list = passwordHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(1);
});
test('Returns list with good profile - Random Password', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "password","GenerateRandomPassword": true,"RandomPasswordLength": 10,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    list = passwordHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(1);
});