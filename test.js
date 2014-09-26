var async = require('async');

var f1 = require('./lib/frost.js').frost({}).generate_keypair().listen(3001);
var f2 = require('./lib/frost.js').frost({}).generate_keypair().listen(3002);
var f3 = require('./lib/frost.js').frost({}).generate_keypair().listen(3003);

f1.on('peer_close', function(p) {
  console.log('f1 CLOSE ' + p.public_key + ' ' + p.url);
});
f2.on('peer_close', function(p) {
  console.log('f2 CLOSE ' + p.public_key + ' ' + p.url);
});
f3.on('peer_close', function(p) {
  console.log('f3 CLOSE ' + p.public_key + ' ' + p.url);
});

async.parallel([
  function(cb_) {
    f1.peer_connect('http://localhost:3002', f2.public_key(), cb_);
  },
  function(cb_) {
    f1.peer_connect('http://localhost:3003', f3.public_key(), cb_);
  },
  function(cb_) {
    f2.peer_connect('http://localhost:3001', f3.public_key(), cb_);
  },
  function(cb_) {
    f2.peer_connect('http://localhost:3003', f3.public_key(), cb_);
  },
  function(cb_) {
    f3.peer_connect('http://localhost:3001', f1.public_key(), cb_);
  },
  function(cb_) {
    f3.peer_connect('http://localhost:3002', f2.public_key(), cb_);
  },
], function(err) {
  if(err) {
    console.log(err);
    process.exit(0);
  }

  f1.receive('test', function(from, sha, payload) {
    console.log('f1 RECEIVED test ' + from + ' ' + payload);
  });
  f1.send('test', 'foo bar', function(err, sha) {
    if(err) {
      console.log(err);
    }
    else {
      console.log('OK: ' + sha);
    }
  });

  f2.receive('test', function(from, sha, payload) {
    console.log('f2 RECEIVED test ' + from + ' ' + payload);
    if(from === f1.public_key()) {
      f2.send('test', 'foo bar 2', function(err, sha) {
        if(err) {
          console.log(err);
        }
        else {
          console.log('OK: ' + sha);
        }
      });
    }
  });
});
