/**
 * Created by tabishrizvi on 28/12/15.
 */

var config = require('./config');
var mysql      = require('mysql');


var connection = mysql.createConnection(config[process.env.NODE_ENV || 'test'].db);

connection.connect(function(err) {
    if (err) {
        console.error('error connecting: ' + err.stack);
        return;
    }

    console.log('connected as id ' + connection.threadId);
});


module.exports = connection;