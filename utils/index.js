/**
 * Created by Tabish on 1/12/16.
 */

var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
var config = require('../config');
var _ = require('underscore');



/**
 * Send API response
 * @param res
 * @param status
 * @param message
 * @param data
 */

module.exports.sendResponse = function(res,status,message,data){

    var response =  {
        message:message,
        data:data
    };

    res.status(status).send(response);
};




/**
 * customer validator functions for express-validator
 * @type {{isArray: exports.customValidators.isArray, isValidEnum: exports.customValidators.isValidEnum, isValidPassword: exports.customValidators.isValidPassword}}
 */


module.exports.customValidators = {

    isArray: function (value) {
        return Array.isArray(value);
    },
    isValidEnum: function(value,enums){
        return enums.indexOf((value))!=-1;
    },
    isValidPassword:function(value){
        return (new RegExp(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[$@$!%*#?&_])[A-Za-z\d$@$!%*#?&_]+$/)).test(value);
    },
    isValidSecret: function(value){
        return config[process.env.NODE_ENV || 'dev'].secret==value
    },
    isObjectOfGivenSchema: function(value,schemaObject){

        var self =this;

        if(typeof value != 'object'){
            return false;
        }

        var specifiedKeys = _.allKeys(schemaObject);
        var receivedKeys = _.allKeys(value);

        if((_.difference(specifiedKeys,receivedKeys).length!=0 || (_.difference(receivedKeys,specifiedKeys).length!=0))){
            return false;
        }

        for(var i=0;i<specifiedKeys.length;i++){

            if(typeof schemaObject[specifiedKeys[i]] != 'function' && typeof  schemaObject[specifiedKeys[i]] !='object'){
                return false;
            }

            if(typeof schemaObject[specifiedKeys[i]] == 'object'){

                if(self.isObjectOfGivenSchema(value[specifiedKeys[i]],schemaObject[specifiedKeys[i]])==false){
                    return false;
                }
            }
            else{
                switch (schemaObject[specifiedKeys[i]].name){

                    case "String":
                        if(typeof value[specifiedKeys[i]] != 'string'){
                            return false;
                        }
                        break;

                    case "Number":
                        if(typeof value[specifiedKeys[i]] != 'number'){
                            return false;
                        }
                        break;

                    case "Boolean":
                        if(typeof value[specifiedKeys[i]] != 'boolean'){
                            return false;
                        }
                        break;

                    case "Array":
                        if(!Array.isArray(value[specifiedKeys[i]])){
                            return false;
                        }
                        break;

                    case "Object":
                        if(typeof value[specifiedKeys[i]] != 'object'){
                            return false;
                        }
                        break;

                    default:
                        if(typeof value[specifiedKeys[i]] != 'string'){
                            return false;
                        }
                        break;

                }

            }
        }


        return true;
    },
    isArrayOfGivenType: function(value,givenType){

        var self = this;


        if(Array.isArray(value)==false){
            return false;
        }

        var error = _.some(value,function(element){

            if(typeof givenType != 'function' && typeof  givenType !='object'){
                return true;
            }

            if(typeof givenType == 'object'){

                return !(self.isObjectOfGivenSchema(element,givenType));
            }
            else {
                switch (givenType.name) {

                    case "String":
                        return !(typeof element =='string');

                    case "Number":
                        return !(typeof element =='number');

                    case "Boolean":
                        return !(typeof element =='boolean');

                    case "Array":
                        return !(Array.isArray(element));

                    case "Object":
                        return !(typeof element =='object');

                    default:
                        return !(typeof element =='string');
                }
            }

        });

        return !error;
    }

};

/**
 * Generating hash of password using bcrypt
 * @param rawPass
 * @param cb
 */
module.exports.hashPassword = function(rawPass,cb){

    bcrypt.genSalt(10,function(err,salt){
        if(err){
            cb(err);
        }
        else{
            bcrypt.hash(rawPass,salt,function(err,hash){
                if(err){
                    cb(err);
                }
                else {
                    cb(null,hash);
                }
            });
        }
    });
};

/**
 * Compare password and its hash using bcrypt
 * @param pass
 * @param hash
 * @param cb
 */

module.exports.comparePassword = function(pass,hash,cb){

    bcrypt.compare(pass,hash,cb);
};



/**
 * Append expiration date to authenticationPayload and generate its access token using jwt
 * @param authenticationPayload
 * @param ttl
 * @param callback
 */
module.exports.createAccessToken = function(authenticationPayload,callback){




    jwt.sign(authenticationPayload,config[process.env.NODE_ENV || 'test'].HMACKey,{},callback);
};


/**
 * Validates access token by verifying it and checking againt the revoke list.If valid returns decoded authenticationPayload
 * @param token
 * @param callback
 */

module.exports.verifyAccessToken = function(token,callback){

    jwt.verify(token,config[process.env.NODE_ENV || 'test'].HMACKey,callback);
};





