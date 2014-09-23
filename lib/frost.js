/**
 * frost: frost.js
 *
 * Copyright (c) 2014, Stanislas Polu. All rights reserved.
 *
 * @author: spolu
 *
 * @log:
 * - 2014-09-19 spolu   Creation
 */
"use strict"

var common = require('./common.js');
var events = require('events');

var protocol = require('fba').protocol;
var node = require('fba').node;

// ## frost
//
// ```
// @spec  { public_key, private_key }
// ```
var frost = function(spec, my) {
  var my = my || {};
  spec = spec || {};
  var _super = {};

  my.node = node({
    public_key: spec.public_key,
    private_key: spec.private_key
  });
  my.protocol = protocol({ node: my.node });
  my.wss = null;

  //
  // ### _public_
  //
  var public_key;        /* public_key(); */
  var private_key;       /* public_key(); */
  var generate_keypair;  /* generate_keypair(); */

  var peer_connect;      /* peer_connect(url, public_key); */
  var peer_list;         /* peer_list(); */
  var peer_disconnect;   /* peer_disconnect(public_key); */

  var quorum_list;       /* quorum_list(); */
  var quorum_add;        /* quorum_add(q); */
  var quorum_remove;     /* quorum_remove(q); */
  var quorum_suggest;    /* quorum_suggest(replace); */

  var listen;            /* listen(port); */

  var on;                /* on(channel, cb_); */
  var emit;              /* emit(channel, sequence, payload, cb_); */

  //
  // ### _private_
  //

  //
  // ### _that_
  //
  var that = {};

  /****************************************************************************/
  /* PRIVATE HELPERS */
  /****************************************************************************/

  /****************************************************************************/
  /* PUBLIC METHODS */
  /****************************************************************************/
  // ### public_key
  //
  // Returns the public_key for this instance
  public_key = function() {
    return my.node.public_key();
  };

  // ### private_key
  //
  // Returns the private_key for this instance
  private_key = function() {
    return my.node.private_key();
  };

  // ### generate_keypair
  //
  // Generates a keypair for that instance and sets its public and private key 
  // internal values
  // ```
  // @seed {buffer} optional seed
  // ```
  generate_keypair = function(seed) {
    my.node.generate_keypair(seed);
    return that;
  };


  // ### peer_connect
  //
  // Connects to the specified peer
  // ```
  // @url        {string} websocket URL
  // @public_key {string} the public key to associate with this peer
  // ```
  peer_connect = function(url, public_key) {
    var ws = new (require('ws'))(url);
    ws.on('error', function(err) {
      that.emit('peer_error', {
        error: err,
        public_key: public_key,
        url: url
      });
    });
    ws.on('close', function(err) {
      that.emit('peer_close', {
        public_key: public_key,
        url: url
      });
      delete my.peers[public_key];
    });
    ws.on('open', function() {
      my.peers[public_key] = {
        public_key: public_key,
        url: url,
        ws: ws
      };
      that.emit('peer_open', {
        public_key: public_key,
        url: url
      });
    });
    return that;
  };

  // ### peer_list
  //
  // Lists the peer to which we are currently connected
  peer_list = function() {
    return Object.keys(my.peers).map(function(pk) {
        return my.peers[pk];
    });
  };

  // ### peer_disconnect
  //
  // Disconeects from the specified peer
  // ```
  // @public_key {string} the public key associated with the peer to disconnect
  // ```
  peer_disconnect = function(public_key) {
    if(my.peers[public_key]) {
      my.peers[public_key].ws.close();
      delete my.peers[public_key];
    };
    return that;
  };


  // ### quorum_list
  //
  // Lists the quorums recognized by this frost instance
  quorum_list = function() {
    var quorums = [];
    my.node.quorums().for_each(function(q) {
      quorums.push(q);
    });
    return quorums;
  };

  // ### quorum_add
  //
  // Adds a new quorum to be recognized by this instance
  // ```
  // @quorum {array} a quorum to add (array of public_key)
  // ```
  quorum_add = function(q) {
    my.node.quorums().add_quorum(q);
    return that;
  };

  // ### quorum_remove
  //
  // Removes a quorum from the list of quorums recognized by this instance
  // ```
  // @quorum {array} a quroum to remove (array of public_key)
  // ```
  quorum_remove = function(q) {
    my.node.quorums().remove_quorum(q);
    return that;
  };

  // ### quorum_suggest
  // 
  // Suggest a list of quorums for the peers this instance is connected to
  // ```
  // @replace {boolean} 
  // ```
  quorum_suggest = function(replace) {
  };


  // ### listen
  //
  // Starts a websocket server listening to client/peers frosts instances
  // ```
  // @port   {number} port number
  // @throws {error} from ws library
  // ```
  listen = function(port) {
    if(my.wss) {
      my.wss.close();
    }
    my.wss = new (require('ws').Server)({ port: port });

    my.wss.on('connection', function(ws) {
      ws.on('message', function(message) {
        console.log('received: %s', message);
      });
      ws.send('something');
    });

    return that;
  };



  common.method(that, 'private_key', private_key, _super);
  common.method(that, 'public_key', public_key, _super);
  common.method(that, 'generate_keypair', generate_keypair, _super);

  common.method(that, 'peer_connect', peer_connect, _super);
  common.method(that, 'peer_list', peer_list, _super);
  common.method(that, 'peer_disconnect', peer_disconnect, _super);

  common.method(that, 'quorum_list', quorum_list, _super);
  common.method(that, 'quorum_add', quorum_add, _super);
  common.method(that, 'quorum_remove', quorum_remove, _super);
  common.method(that, 'quorum_suggest', quorum_suggest, _super);

  common.method(that, 'listen', listen, _super);

  common.method(that, 'on', on, _super);
  common.method(that, 'emit', emit, _super);


  return that;
};

exports.frost = frost;
