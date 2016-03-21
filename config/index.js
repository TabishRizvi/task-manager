/**
 * Created by tabishrizvi on 27/12/15.
 */


module.exports = {


    test:{
        port:7001,
        db:{
            host:'localhost',
            port:3306,
            user:'user',
            password:'*********',
            database:'task-manager',
            dateStrings:true
        },
        task_types:[
            {id:1,name:'Appointment'},
            {id:2,name:'Delivery/Pickup'},
            {id:3,name:'Meeting'}
        ],
        HMACKey:'********************',
        secret:'*************'

    },

    live:{
        port:3001,
        db:{
            host:'localhost',
            port:3306,
            user:'user',
            password:'*********',
            database:'task-manager',
            dateStrings:true
        },
        task_types:[
            {id:1,name:'Appointment'},
            {id:2,name:'Delivery/Pickup'},
            {id:3,name:'Meeting'}
        ],
        HMACKey:'********************',
        secret:'*************'

    }
};


