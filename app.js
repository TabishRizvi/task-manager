var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var chalk = require('chalk');
var async = require('async');
var loggerOne = require('logger-one');
var morgan = require('morgan');
var methodOverride = require('method-override');

var connection = require('./db');

var routes = require('./routes');

var config = require('./config');

var app = express();

app.set('port',config[process.env.NODE_ENV || 'test'].port);
//app.use(methodOverride());

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, authorization");
    res.header("Access-Control-Allow-Methods", "GET,POST,DELETE,PUT,OPTIONS");
    next();
});



app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));



if(process.env.NODE_ENV=='live'){
    app.use(loggerOne());
}
else{
    app.use(morgan('dev', {immediate:false}));

}



app.use('/api', routes.api);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'test') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.send({
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.send( {
    message: err.message,
    error: {}
  });
});


var server = app.listen(app.get('port'),function(){
   console.log(chalk.yellow("Server running on port\t===============>\t"),chalk.black.bgYellow.bold(server.address().port));
});


process.on('SIGINT', function() {


    connection.end(function(err) {
        console.log(chalk.yellow("Server stopped at \t===============>\t"),chalk.black.bgYellow.bold((new Date)));
        process.exit(0);
    });


});



