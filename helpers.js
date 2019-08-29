let helpers = new Object();
helpers.createErrorMessage = function(uuid, message){
    let errorObj = new Object();
    errorObj.uuid = uuid;
    errorObj.errorText = message;
    return errorObj;
}
module.exports = helpers;