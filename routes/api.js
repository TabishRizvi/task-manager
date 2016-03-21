/**
 * Created by Tabish on 1/12/16.
 */
var express = require('express');
    router = express.Router();
    _ = require('underscore');
    async = require('async');
    moment = require('moment');
    validator = require('validator');
    connection = require('../db');

var utils = require('../utils');
var config = require('../config');

validator.extend('isLat',function(value){
    return !isNaN(value) && value>=-90 && value<=90
});

validator.extend('isLng',function(value){
    return !isNaN(value) && value>=-180 && value<=180
});



router.post('/register',
    function (req, res, next) {


        if(_.isUndefined(req.body.email) || _.isUndefined(req.body.first_name) || _.isUndefined(req.body.last_name) || _.isUndefined(req.body.password) || _.isUndefined(req.body.phone)){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }

        if(!validator.isEmail(req.body.email)){
            utils.sendResponse(res,400,'email is invalid',{});
            return;
        }

        if(!validator.isLength(req.body.password,{min:6})){
            utils.sendResponse(res,400,'password is invalid',{});
            return;
        }

        if(!validator.isLength(req.body.phone,{min:10,max:10})){
            utils.sendResponse(res,400,'phone is invalid',{});
            return
        }





        next();

    },
    function (req, res, next) {

        var payload = {
            email: validator.normalizeEmail(req.body.email),
            firstName:req.body.first_name,
            lastName:req.body.last_name,
            password:req.body.password,
            phone:req.body.phone
        };


        async.waterfall([
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `email`=?";

                connection.query(sql,[payload.email],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length>0){
                            cb({
                                code:409,
                                message:'Email is already registered'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                })

            },
            function(cb){

                utils.hashPassword(payload.password,function(err,hash){
                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        payload.password = hash;
                        console.log(hash);
                        cb(null);
                    }
                });
            },
            function(cb){

                var currentUTC = moment.utc();
                var sql = "INSERT INTO `users`(`email`,`first_name`,`last_name`,`password`,`phone`,`registered_on`)  VALUES(?,?,?,?,?,?)";

                connection.query(sql,[payload.email,payload.firstName,payload.lastName,payload.password,payload.phone,currentUTC.format('YYYY-MM-DD HH:mm:ss')],function(err,result){

                    if(err){
                        console.log(err);
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        console.log(result);
                        cb(null,{
                            code:201,
                            message:"user created",
                            data:{}
                        });
                    }
                })

            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);


router.post('/login',
    function (req, res, next) {


        if(_.isUndefined(req.body.email) || _.isUndefined(req.body.password)){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }

        if(!validator.isEmail(req.body.email)){
            utils.sendResponse(res,400,'email is invalid',{});
            return;
        }



        next();

    },
    function (req, res, next) {

        var payload = {
            email: validator.normalizeEmail(req.body.email),
            password:req.body.password
        };


        async.waterfall([
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `email`=?";

                connection.query(sql,[payload.email],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0){
                            cb({
                                code:401,
                                message:'Email not registered'
                            });
                        }
                        else{
                            cb(null,result[0]);
                        }
                    }
                });

            },
            function(user,cb){

                utils.comparePassword(payload.password,user.password,function(err,same){
                    if(!same){
                        cb({
                            code:401,
                            message:'Password is incorrect'
                        });
                    }
                    else{
                        cb(null,user);
                    }
                })
            },

            function(user,cb){

                utils.createAccessToken({userId:user.id},function(accessToken){
                    user.access_token = accessToken;
                    cb(null,user);
                })
            },
            function(user,cb){

                var sql = 'UPDATE `users` SET `access_token`=? WHERE `id`=?';

                connection.query(sql,[user.access_token,user.id],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.affectedRows==0){
                            cb({
                                code:404,
                                message:'User not found'
                            });
                        }
                        else{
                            cb(null,{
                                code:200,
                                message:"Successful login",
                                data:{
                                    user_id:user.id,
                                    access_token:user.access_token,
                                    email:user.email
                                }
                            });
                        }
                    }
                })
            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);


router.get('/logout',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.userId = decoded.userId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){


                var sql = "UPDATE `users` SET `access_token`= '' WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.affectedRows==0){
                            cb({
                                code:500,
                                message:'Internal Server Error'
                            });
                        }
                        else{
                            cb(null,{
                                code:200,
                                message:'Successfully logged out',
                                data:{}
                            });
                        }
                    }
                });


            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);



router.post('/create-task',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ||  _.isUndefined(req.body.type_id) || _.isUndefined(req.body.task_name) || _.isUndefined(req.body.task_datetime) || _.isUndefined(req.body.formatted_address) || _.isUndefined(req.body.lat) || _.isUndefined(req.body.lng)){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        if(_.find(config[process.NODE_ENV || 'test'].task_types,function(element){
                return element.id==parseInt(req.body.type_id);
            })===undefined){
            utils.sendResponse(res,400,'type_id is invalid',{});
            return;

        }

        if(parseInt(req.body.type_id)==3){
            if(_.isUndefined(req.body.meeting_list) ){
                utils.sendResponse(res,400,'Some parameters missing',{});
                return;
            }

            if(!_.isArray(req.body.meeting_list)){
                utils.sendResponse(res,400,'meeting_list must be an array',{});
                return;
            }

        }
        else{
            if(_.isUndefined(req.body.sender_id) || _.isUndefined(req.body.receiver_id)){
                utils.sendResponse(res,400,'Some parameters missing',{});
                return;
            }
        }

        if(!validator.isISO8601(req.body.task_datetime)){
            utils.sendResponse(res,400,'task_datetime is invalid',{});
        }

        if(!validator.isLat(req.body.lat) || !validator.isLng(req.body.lng)){
            utils.sendResponse(res,400,'lat,lng are invalid',{});
        }



        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization,
            typeId  :       parseInt(req.body.type_id),
            taskDateTime    :   moment.utc(req.body.task_datetime),
            address :       [req.body.formatted_address,Number(req.body.lat),Number(req.body.lng)],
            senderId:   parseInt(req.body.type_id)==3?"":req.body.sender_id,
            receiverId: parseInt(req.body.type_id)==3?"":req.body.receiver_id,
            senderStatus:parseInt(req.body.type_id)==3?"":"PENDING" ,
            receiverStatus:parseInt(req.body.type_id)==3?"":"PENDING",
            meetingList:    parseInt(req.body.type_id)!=3?"":req.body.meeting_list,
            taskName:req.body.task_name

        };


        async.waterfall([
            function(cb){
              utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                  if(err){
                      cb({
                          code:401,
                          message:'authorization failed'
                      });
                  }
                  else{
                      payload.userId = decoded.userId;
                      cb(null);
                  }
              })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){

                var idsToBeVerified;
                if(payload.typeId==3){
                    idsToBeVerified=payload.meetingList;
                }
                else{
                    idsToBeVerified=[payload.senderId,payload.receiverId];
                }


                var sql = "SELECT * FROM `users` WHERE `id` IN (?)";

                connection.query(sql,[idsToBeVerified],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{

                        if(result.length!=idsToBeVerified.length){
                            cb({
                                code:400,
                                message:'some member ids are invalid'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });
            },

            function(cb){
                var sql = "SELECT * FROM `addresses` WHERE `formatted_address`=? && `lat`=? && `lng`=?";

                connection.query(sql,payload.address,function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0){
                            payload.addressId = null;
                        }
                        else{
                            payload.addressId = result[0].id;
                        }
                        cb(null);
                    }
                });
            },


            function(cb){

                if(!_.isNull(payload.addressId)){
                    cb(null);
                    return;
                }

                var sql = 'INSERT INTO `addresses`(`formatted_address`,`lat`,`lng`) VALUES(?,?,?)';

                connection.query(sql,payload.address,function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        payload.addressId = result.insertId;
                        cb(null);
                    }
                });
            },


            function(cb){

                var currentUTC = moment.utc();

                var sql = 'INSERT INTO `tasks`(`type_id`,`organizer_id`,`sender_id`,`receiver_id`,`created_datetime`,`task_datetime`,`address_id`,`sender_status`,`receiver_status`,`task_name`) VALUES(?,?,?,?,?,?,?,?,?,?)';

                connection.query(sql,[payload.typeId,payload.userId,payload.senderId,payload.receiverId,currentUTC.format('YYYY-MM-DD HH:mm:ss'),payload.taskDateTime.format('YYYY-MM-DD HH:mm:ss'),payload.addressId,payload.senderStatus,payload.receiverStatus,payload.taskName],function(err,result){
                    console.log(err);
                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        payload.taskId = result.insertId;
                        cb(null);
                    }
                });
            },

            function(cb){

                if(payload.typeId!=3){
                    cb(null);
                    return;
                }

                async.each(payload.meetingList,function(element,callback){

                    var sql = "INSERT INTO `meeting_lists`(`meeting_id`,`member_id`,`status`) VALUES(?,?,'PENDING')";


                    connection.query(sql,[payload.taskId,element],function(err,result){

                        if(err){
                            callback({
                                code:500,
                                message:'Internal Server Error'
                            });
                        }
                        else{
                            callback(null);
                        }
                    });
                },function(err){
                    if(err){
                        cb(err);
                    }
                    else{
                        cb(null);
                    }
                });
            },

            function(cb){

                cb(null,{
                    code:201,
                    message:'task created',
                    data:{
                        taskId:payload.taskId
                    }
                });

            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);


router.get('/tasks/organized',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.userId = decoded.userId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){




                var sql = "SELECT `id`,`task_name`,`task_datetime`,`type_id`  FROM `tasks` WHERE `organizer_id` =?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{


                        var list = _.each(result,function(element,index,list){
                            list[index].task_id = element.id;
                            list[index].task_datetime = (moment.utc(element.task_datetime,"YYYY-MM-DD HH:mm:ss")).toISOString();
                            list[index] = _.omit(list[index],'id');
                        });

                        cb(null,{
                            code:200,
                            message:list.length+' task(s) found',
                            data:list
                        })
                    }
                });
            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);


router.put('/tasks/cancel/:taskId',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ||_.isUndefined(req.params.taskId) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization,
            taskId : req.params.taskId

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.userId = decoded.userId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){




                var sql = "SELECT *  FROM `tasks` WHERE `id` =?";

                connection.query(sql,[payload.taskId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{


                        if(result.length==0){
                            cb({
                                code:400,
                                message:'Invalid task id'
                            });
                        }
                        else if(result[0].organizer_id!=payload.userId){
                            cb({
                                code:401,
                                message:'Only organizer of the task can cancel it'
                            });
                        }
                        else {
                            cb(null);
                        }


                    }
                });
            },

            function(cb){

                var sql = "UPDATE `tasks` SET `cancelled`=1 WHERE `id`=?";

                connection.query(sql,[payload.taskId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.affectedRows==0){
                            cb({
                                code:400,
                                message:'Invalid task id'
                            });
                        }
                        else{
                            cb(null,{
                                code:200,
                                message:'Task cancelled',
                                data:{
                                    task_id:payload.taskId
                                }
                            });
                        }

                    }
                });
            }

        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);



router.put('/tasks/respond/:taskId',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ||_.isUndefined(req.params.taskId) ||  _.isUndefined(req.query.response) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }

        if(_.indexOf(['YES','MAYBE','NO'],req.query.response)==-1){
            utils.sendResponse(res,400,'response is invalid',{});
            return;
        }



        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization,
            taskId : req.params.taskId,
            response:req.query.response

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.userId = decoded.userId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){




                var sql = "SELECT *  FROM `tasks` WHERE `id` =?";

                connection.query(sql,[payload.taskId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{


                        if(result.length==0){
                            cb({
                                code:400,
                                message:'Invalid task id'
                            });
                        }
                        else {
                            payload.taskData = result[0];
                            cb(null);
                        }


                    }
                });
            },


            function(cb){

                if(payload.taskData.type_id==3){
                    cb(null);
                    return;
                }

                if(payload.taskData.sender_id!=payload.userId && payload.taskData.receiver_id!=payload.userId ){
                    cb({
                        code:401,
                        message:'unauthorized for this operation'
                    });
                }

                else{
                    var sql;
                    if(payload.taskData.sender_id==payload.userId){

                        sql = "UPDATE `tasks` SET `sender_status`=? WHERE `id`=?";
                    }
                    else{
                        sql = "UPDATE `tasks` SET `receiver_status`=? WHERE `id`=?";
                    }


                    connection.query(sql,[payload.response,payload.taskId],function(err,result){

                        if(err){
                            cb({
                                code:500,
                                message:'Internal Server Error'
                            });
                        }
                        else{


                            if(result.affectedRows==0){
                                cb({
                                    code:400,
                                    message:'Invalid task id'
                                });
                            }
                            else {
                                cb(null);
                            }


                        }
                    });
                }

            },


            function(cb){

                if(payload.taskData.type_id!=3){
                    cb(null);
                    return;
                }

                var sql = "UPDATE `meeting_lists` SET `status`=? WHERE `member_id`=? AND `meeting_id`=?"

                connection.query(sql,[payload.response,payload.userId,payload.taskId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{


                        if(result.affectedRows==0){
                            cb({
                                code:401,
                                message:'unauthorized for this operation'
                            });
                        }
                        else {
                            cb(null);
                        }


                    }
                });
            },

            function(cb){


                cb(null,{
                    code:200,
                    message:'Response recorded',
                    data:{
                        task_id:payload.taskId,
                        type_id:payload.taskData.type_id
                    }
                })
            }

        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);




router.get('/tasks/assigned',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) || _.isUndefined(req.query.status)){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        if(_.indexOf(['PENDING','DONE'],req.query.status)==-1){
            utils.sendResponse(res,400,'status is invalid',{});
            return;
        }



        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization,
            status:req.query.status=="DONE"?["YES","MAYBE","NO"]:["PENDING"]

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.userId = decoded.userId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){




                var sql = "SELECT `temp_table1`.*, `users`.email as organizer_email,concat(`users`.`first_name`,' ',`users`.`last_name`) as organizer_name FROM " +
                    " (SELECT `tasks`.`id` as task_id,`tasks`.`task_name`,`tasks`.`task_datetime`,`tasks`.`type_id` ,`tasks`.`organizer_id` FROM `tasks`, " +
                    "(SELECT `meeting_id`,`status` FROM `meeting_lists` " +
                    "WHERE `member_id`=?) as temp_table" +
                    " WHERE (`tasks`.`id`=`temp_table`.`meeting_id` AND `temp_table`.`status` IN (?)) OR (`tasks`.`sender_id`=?  AND `tasks`.`sender_status` IN (?)) OR (`tasks`.`receiver_id`=?  AND `tasks`.`receiver_status` IN (?))) as `temp_table1`,`users`" +
                    " WHERE `temp_table1`.`organizer_id`=`users`.`id`";

                connection.query(sql,[payload.userId,payload.status,payload.userId,payload.status,payload.userId,payload.status],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{


                        var list = _.each(result,function(element,index,list){
                            list[index].task_datetime = (moment.utc(element.task_datetime,"YYYY-MM-DD HH:mm:ss")).toISOString();
                        });

                        cb(null,{
                            code:200,
                            message:list.length+' task(s) found',
                            data:list
                        })
                    }
                });
            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);


router.get('/tasks/:taskId',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ||  _.isUndefined(req.params.taskId) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization,
            taskId:req.params.taskId

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.userId = decoded.userId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){

                var sql = "SELECT `type_id` FROM `tasks` WHERE `id`=?";

                connection.query(sql,[payload.taskId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0){
                            cb({
                                code:400,
                                message:'Invalid task id'
                            });
                        }
                        else{
                            payload.typeId=result[0].type_id;
                            cb(null);
                        }
                    }
                });
            },
            function(cb){
                var sql;
                if(payload.typeId==3){
                    sql = "SELECT `temp_table`.*, `users`.email as organizer_email,concat(`users`.`first_name`,' ',`users`.`last_name`) as organizer_name FROM" +
                        " (SELECT `tasks`.*,`addresses`.`formatted_address`,`addresses`.`lat`,`addresses`.`lng` FROM `tasks` JOIN `addresses` ON `tasks`.`address_id`=`addresses`.`id`" +
                        " WHERE `tasks`.`id`=?) as `temp_table`,`users`" +
                        " WHERE  `temp_table`.`organizer_id`=`users`.`id`"
                }
                else{
                    sql = "SELECT `temp_table1`.*,`users`.email as organizer_email,concat(`users`.`first_name`,' ',`users`.`last_name`) as organizer_name  FROM" +
                        "(SELECT `temp_table`.*,`users`.email as receiver_email,concat(`users`.`first_name`,' ',`users`.`last_name`) as receiver_name  FROM " +
                        "(SELECT `temp`.*, `users`.`email` as sender_email ,concat(`users`.`first_name`,' ',`users`.`last_name`) as sender_name FROM " +
                        "(SELECT `tasks`.*,`addresses`.`formatted_address`,`addresses`.`lat`,`addresses`.`lng` FROM `tasks` JOIN `addresses` ON `tasks`.`address_id`=`addresses`.`id` " +
                        "WHERE `tasks`.`id`=?) as `temp`,`users` " +
                        "WHERE  `temp`.`sender_id`=`users`.`id`) as `temp_table` , `users` " +
                        " WHERE `temp_table`.`receiver_id`=`users`.`id`) as `temp_table1`, `users` " +
                        "WHERE `temp_table1`.`organizer_id`=`users`.`id`";
                }


                connection.query(sql,[payload.taskId],function(err,result){
                    console.log(err);
                    console.log(result);

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{

                        if(result.length==0){
                            cb({
                                code:400,
                                message:'Invalid task id'
                            });
                        }
                        else{
                            payload.taskData = result[0];
                            cb(null);
                        }

                    }
                });
            },

            function(cb){
                console.log("=======-");
                if(payload.typeId!=3){
                    cb(null);
                    return;
                }

                var sql = "SELECT `meeting_lists`.`member_id`,`meeting_lists`.`status` , `users`.email as member_email,concat(`users`.`first_name`,' ',`users`.`last_name`) as member_name  FROM `meeting_lists` JOIN `users` ON `meeting_lists`.`member_id`=`users`.`id` WHERE `meeting_id`=?"

                connection.query(sql,[payload.taskId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        payload.taskData.meeting_list = result;
                        cb(null);
                    }
                });
            },
            function(cb){

                var outputData = {
                    task_id : payload.taskData.id,
                    task_name:payload.taskData.task_name,
                    type_id : payload.taskData.type_id,
                    organizer:{
                        organizer_id : payload.taskData.organizer_id,
                        organizer_name : payload.taskData.organizer_name,
                        organizer_email : payload.taskData.organizer_email

                    },
                    address:{
                        formatted_address : payload.taskData.formatted_address,
                        lat : payload.taskData.lat,
                        lng : payload.taskData.lng

                    },
                    created_datetime:(moment.utc(payload.taskData.created_datetime,"YYYY-MM-DD HH:mm:ss")).toISOString(),
                    task_datetime:(moment.utc(payload.taskData.task_datetime,"YYYY-MM-DD HH:mm:ss")).toISOString()
                };

                if(payload.typeId==3){
                    outputData.meeting_list = payload.taskData.meeting_list;
                }
                else{
                    outputData.sender = {
                        sender_id : payload.taskData.sender_id,
                        sender_name : payload.taskData.sender_name,
                        sender_email : payload.taskData.sender_email,
                        sender_status:payload.taskData.sender_status
                    };


                    outputData.receiver = {
                        receiver_id : payload.taskData.receiver_id,
                        receiver_name : payload.taskData.receiver_name,
                        receiver_email : payload.taskData.receiver_email,
                        receiver_status:payload.taskData.receiver_status
                    }

                }


                cb(null,{
                    code:200,
                    message:'Task details retrieved',
                    data:outputData
                });
            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);

router.get('/users',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ||  _.isUndefined(req.query.key) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }

        console.log(req.query.key);


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization,
            key : req.query.key

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.userId = decoded.userId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `users` WHERE `id`=?";

                connection.query(sql,[payload.userId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){

                var sql = "SELECT `id` as user_id, concat(`first_name`,' ',`last_name`) as name,`email` FROM `users` " ;

                console.log("+++++++++++++++++",payload.key);
                var words = payload.key.split(" ");
                console.log("+++++++++++++++++",words);

                var params;
                if(words.length==2){
                    params = ['%'+words[0]+'%','%'+words[1]+'%','%'+words[0]+'%','%'+words[1]+'%'];
                    sql += "WHERE `first_name` LIKE ? OR `first_name` LIKE ? OR `last_name` LIKE ?  OR `last_name` LIKE ? LIMIT 5";
                }
                else{
                    params = ['%'+payload.key+'%','%'+payload.key+'%'];
                    sql += "WHERE `first_name` LIKE ? OR `last_name` LIKE ?  LIMIT 5";
                }

                connection.query(sql,params,function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        cb(null,{
                            code:200,
                            message: 'No of results : '+result.length,
                            data:result
                        })
                    }
                });
            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);


router.post('/admin/login',
    function (req, res, next) {


        if(_.isUndefined(req.body.email) || _.isUndefined(req.body.password)){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }

        if(!validator.isEmail(req.body.email)){
            utils.sendResponse(res,400,'email is invalid',{});
            return;
        }



        next();

    },
    function (req, res, next) {

        var payload = {
            email: validator.normalizeEmail(req.body.email),
            password:req.body.password
        };


        async.waterfall([
            function(cb){
                var sql = "SELECT * FROM `admins` WHERE `email`=?";

                connection.query(sql,[payload.email],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0){
                            cb({
                                code:401,
                                message:'Email not registered'
                            });
                        }
                        else{
                            cb(null,result[0]);
                        }
                    }
                });

            },
            function(admin,cb){

                utils.comparePassword(payload.password,admin.password,function(err,same){
                    if(!same){
                        cb({
                            code:401,
                            message:'Password is incorrect'
                        });
                    }
                    else{
                        cb(null,admin);
                    }
                })
            },

            function(admin,cb){

                utils.createAccessToken({adminId:admin.id},function(accessToken){
                    admin.access_token = accessToken;
                    cb(null,admin);
                })
            },
            function(admin,cb){

                var sql = 'UPDATE `admins` SET `access_token`=? WHERE `id`=?';

                connection.query(sql,[admin.access_token,admin.id],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.affectedRows==0){
                            cb({
                                code:404,
                                message:'User not found'
                            });
                        }
                        else{
                            cb(null,{
                                code:200,
                                message:"Successful login",
                                data:{
                                    user_id:admin.id,
                                    access_token:admin.access_token,
                                    email:admin.email
                                }
                            });
                        }
                    }
                })
            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);


router.get('/admin/logout',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.adminId = decoded.adminId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `admins` WHERE `id`=?";

                connection.query(sql,[payload.adminId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){


                var sql = "UPDATE `admins` SET `access_token`= '' WHERE `id`=?";

                connection.query(sql,[payload.adminId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.affectedRows==0){
                            cb({
                                code:500,
                                message:'Internal Server Error'
                            });
                        }
                        else{
                            cb(null,{
                                code:200,
                                message:'Successfully logged out',
                                data:{}
                            });
                        }
                    }
                });


            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);




router.get('/admin/users',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.adminId = decoded.adminId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `admins` WHERE `id`=?";

                connection.query(sql,[payload.adminId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){


                var sql = "SELECT `id` as user_id,`email`,concat(`first_name`,' ',`last_name`) as name,`phone`  FROM `users`";

                connection.query(sql,[],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        cb(null,{
                            code:200,
                            message:'Number of users : '+result.length,
                            data:result
                        });
                    }
                });


            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);




router.get('/admin/tasks',
    function (req, res, next) {


        if(_.isUndefined(req.headers.authorization) ){
            utils.sendResponse(res,400,'Some parameters missing',{});
            return;
        }


        next();

    },
    function (req, res, next) {

        var payload = {
            accessToken :   req.headers.authorization

        };


        async.waterfall([
            function(cb){
                utils.verifyAccessToken(payload.accessToken,function(err,decoded){
                    if(err){
                        cb({
                            code:401,
                            message:'authorization failed'
                        });
                    }
                    else{
                        payload.adminId = decoded.adminId;
                        cb(null);
                    }
                })
            },
            function(cb){
                var sql = "SELECT * FROM `admins` WHERE `id`=?";

                connection.query(sql,[payload.adminId],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        if(result.length==0 || result[0].access_token!=payload.accessToken){
                            cb({
                                code:401,
                                message:'authorization failed'
                            });
                        }
                        else{
                            cb(null);
                        }
                    }
                });

            },
            function(cb){


                var sql = "SELECT t.`id` as task_id,t.`type_id`,`organizer_id`,concat(u.`first_name`,' ',u.`last_name`) as organizer_name,created_datetime,task_datetime,task_name  FROM `tasks` as t JOIN `users` as u " +
                        "ON u.`id`= t.`organizer_id`";

                connection.query(sql,[],function(err,result){

                    if(err){
                        cb({
                            code:500,
                            message:'Internal Server Error'
                        });
                    }
                    else{
                        cb(null,{
                            code:200,
                            message:'Number of tasks : '+result.length,
                            data:result
                        });
                    }
                });


            }
        ],function(err,result){
            if(err){
                utils.sendResponse(res,err.code,err.message,{});
            }
            else{
                utils.sendResponse(res,result.code,result.message,result.data)
            }

        });




    }
);



module.exports = router;
