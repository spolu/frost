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
var message = require('fba').message;

// ## frost
//
// ```
// @spec  { public_key, private_key }
// ```
var frost = function(spec, my) {
  var my = my || {};
  spec = spec || {};
  var _super = {};

  my.node = null;
  my.protocol = null;
  my.wss = null;

  my.peers = {};
  my.clients = [];

  /* my.casts[c][f] = {      */
  /*   sha: 'ae23b4...',     */
  /*   sig: 'b3efa5...',     */
  /*   prv: 'b4ef5e...'      */
  /*   pay: 'xxxx'           */
  /* }                       */
  my.casts = {};

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

  var receive;           /* receive(channel, cb_); */
  var send;              /* send(channel, payload, cb_); */

  //
  // ### _private_
  //
  var handle_message;    /* handle_message(data, flags); */

  var verify_cast;       /* verify_cast(from, channel, cast); */
  var generate_cast;     /* generate_cast(channel, prv, cast); */

  var ballot_generator;  /* ballot_generator(slot, x); */
  var ballot_verifier;   /* ballot_verifier(slot, b, node); */
  var ballot_acceptor;   /* ballot_acceptor(slot, b, node); */

  var init;              /* init(); */

  //
  // ### _that_
  //
  var that = {};

  /****************************************************************************/
  /* PRIVATE HELPERS */
  /****************************************************************************/
  // ### handle_message
  //
  // Handles data incoming from clients or peers
  // ```
  // @data  {string} the message
  // @flags {object} the ws flags
  // ```
  handle_message = function(data, flags) {
    try {
      var msg = JSON.parse(data);
      if(msg.t === 'fba') {
        var m = message({}).from_json(msg.m);
        my.protocol.process(m);
      }
    }
    catch(err) {
      common.log.error(common.err('Parsing failed',
                                  'frost:parse_fail'));
    }
  };

  // ### verify_cast
  //
  // Verifies the validiy of a cast (signature, hashs, ...)
  // ```
  // @from    {string} sender public key
  // @channel {string} the channel on which the cast is sent
  // @cast    {object} the cast object
  // ```
  verify_cast = function(from, channel, cast) {
    if(!cast ||
       typeof cast.sha !== 'string' ||
       typeof cast.sig !== 'string' ||
       typeof cast.prv !== 'string' ||
       typeof cast.pay !== 'string') {
      return false;
    }

    if(cast.sha !== common.hash([cast.prv, channel, cast.pay])) {
      return false;
    }

    if(!ed25519.Verify(new Buffer(cast.sha, 'utf8'), 
                       new Buffer(cast.sig, 'base64'),
                       new Buffer(from, 'base64'))) {
      return false;
    }

    return true;
  };

  // ### generate_cast
  //
  // Generates a cast issued by this node
  // ```
  // @channel {string} the channel on which the cast is sent
  // @prv     {string} the previous sha in the chain
  // @payload {string} the cast payload
  // ```
  generate_cast = function(channel, prv, payload) {
    var cast = {
      sha: null,
      sig: null,
      prv: prv,
      pay: payload
    };

    cast.sha = common.hash([cast.prv, channel, cast.pay]);
    cast.sig = ed25519.Sign(new Buffer(cast.sha, 'utf8'), 
                            new Buffer(my.node.private_key(), 'base64')).toString('base64');
    return cast;
  };


  // ### ballot_generator
  //
  // TODO(spolu): more specific ballot_generator. proof of work.
  //
  // ```
  // @slot {object} the slot for which the ballot is generated
  // @x    {string} the value for that ballot
  // ```
  ballot_generator = function(slot, x) {
    var n = 0;
    if(slot.ballot()) {
      n = slot.ballot().n + 1;
    }
    return { n: n, x: x };
  };

  // ### ballot_verifier
  //
  // TODO(spolu): more specific ballot_verifier
  // ```
  // @slot {object} the slot for which the ballot is verified
  // @b    {object} the ballot to verify
  // @node {object} the node that used this ballot in his statement
  // ```
  ballot_verifier = function(slot, b, node) {
    var channel = slot.id().split(':')[0];
    var from = slot.id().split(':')[1];

    try {
      var cast = JSON.parse(b.x);
      if(!verify_cast(from, channel, cast)) {
        return false;
      }
    }
    catch(err) {
      return false;
    }

    if(Date.now() < slot.create_time() + b.n * 1000) {
      common.log.out('Ballot verification failed: ' + Date.now() + ' ' + 
                     (slot.create_time() + b.n * 1000) + ' ' + b.n);
      return false;
    }
    return true;
  };

  // ### ballot_acceptor
  //
  // The ballot acceptor checks that the ballot value is compatible with the
  // local knowledge about that channel and sender
  // ```
  // @slot {object} the slot for which the ballot is verified
  // @b    {object} the ballot to verify
  // @node {object} the node that used this ballot in his statement
  // ```
  ballot_acceptor = function(slot, b, node) {
    var channel = slot.id().split(':')[0];
    var from = slot.id().split(':')[1];

    try {
      var cast = JSON.parse(b.x);

      /* The `cast` has already been verified by the ballot verifier. If we */
      /* have a previous hash we check that it matches with the one we have */
      /* on record. Otherwise, we can pledge to commit that cast. Maybe we  */
      /* were disconnected in which case we'll end up externalizing if the  */
      /* rest of the network externalizes the value.                        */
      if(cast.prv.length > 0 && 
         (!my.casts[channel] ||
          !my.casts[channel][from] ||
          my.casts[channel][from].sha !== cast.prv)) {
        return false;
      }
    }
    catch(err) {
      return false;
    }
    return true;
  };


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
      /* TODO(spolu) reconnect? delete? */
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
    ws.on('message', handle_message);

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
    var peers = that.peer_list().map(function(p) {
      return p.public_key;
    });
    var quorums = [];

    /* We remove ourselve from the peer list in case we are erroneously */
    /* listening to ourself.                                            */
    if(peers.indexOf(my.node.public_key()) !== -1) {
      peers.splice(peers.indexOf(my.node.public_key()), 1);
    }

    /* The following heuristic are far from being perfect, they just aim  */
    /* at avoiding the explosion of the number of quorums when the number */
    /* of peers increase. They are designed to work mainly for the client */
    /* case, working at the edges of the network. Core servers should set */
    /* their quorums more attentively.                                    */

    /* Up to 1 peer (ok if 0) we add all the peers to a unique quorum with */
    /* the intsance node itself.                                           */
    if(peers.length <= 1) {
      quorums.push(peers.slice().push(my.node.public_key()));
    }
    /* With 2 peers we create 2 quorums (any 2 of 3 including self) */
    else if(peers.length === 2) {
      quorums.push([my.node.public_key(), peers[0]],
                   [my.node.public_key(), peers[1]]);
    }
    /* With any higher number, we create O(n) quorum of size 3, including */
    /* the instance node itself, to avoid quorum count explosion.         */
    else {
      for(var i = 0; i < peers.length; i ++) {
        quorums.push([my.node.public_key(), 
                      peers[i], peers[i+1 % peers.length]]);
      }
    }

    if(replace) {
      my.node.quorums().for_each(my.node.quorums().remove_quorum);
      quorums.forEach(my.node.quorums().add_quorum);
    }

    return quorums;
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
      my.clients.push(ws);
      that.emit('client_open', {
        ws: ws
      });

      ws.on('error', function(err) {
        that.emit('client_error', {
          error: err,
          ws: ws
        });
      });
      ws.on('close', function(err) {
        that.emit('client_close', {
          ws: ws
        });
        for(var i = my.clients.length - 1; i >= 0; i--) {
          if(my.clients[i] === ws) {
            my.clients.splice(i, 1);
          }
        }
      });
      ws.on('message', handle_message);
    });

    return that;
  };

  // ### receive
  //
  // Listens to the specified channel for messages
  // ```
  // @channel {string} the channel name
  // @cb_     {function(from, sha, payload)} callback with received message
  // ```
  receive = function(channel, cb_) {
  };

  // ### send
  //
  // Sends a message on the given channel. A sequence number will be attributed 
  // to the message by the protocol.
  // ```
  // @channel  {string} the channel name
  // @payload  {string} the message payload
  // @cb_      {function(err, sha)} callback with eventual error
  // ```
  send = function(channel, payload, cb_) {
    var from = my.node.public_key();
    var slot = channel + ':' + from;

    if(!my.casts[channel]) {
      my.casts[channel] = {};
    }
    if(!my.casts[channel][from]) {
      my.casts[channel][from] = {
        sha: ''
        sig: null,
        prv: null,
        pay: null
      }
    }

    if(typeof payload !== 'string') {
      return cb_(common.err('Invalid payload type: ' + typeof payload,
                            'frost:invalid_payload'));
    }

    var cast = generate_cast(channel,
                             my.casts[channel][from].sha,
                             payload);

    /* We don't need to update `my.casts` here as it will be done by the */
    /* protocol `value` event handler.                                   */
    my.protocol.request(slot, JSON.stringify(cast), 2000, cb_);
  };

  // ### init
  //
  // Initializes the object once it's fully constructed
  init = function() {
    my.node({
      public_key: spec.public_key,
      private_key: spec.private_key
    });
    my.protocol = protocol({ 
      node: my.node 
    });

    my.protocol.on('message', function(m) {
      var data = JSON.stringify({
        t: 'fba',
        m: m.to_json()
      });
      my.clients.forEach(function(ws) {
        ws.send(data);
      });
      Object.keys(my.peers).forEach(function(pk) {
        my.peers[pk].ws.send(data);
      });
    });

    my.protocol.on('value', function(v) {
      var channel = v.slot.split(':')[0];
      var from  = v.slot.split(':')[1];
      try {
        var cast = JSON.parse(v.value);
        if(verify_cast(channel, from, cast)) {
          if(!my.casts[channel]) {
            my.casts[channel] = {};
          }
          my.casts[channel][from] = cast;
          console.log('RECEIVED: ' + v.slot);
        }
        else {
          throw new Error();
        }
      }
      catch(err) {
        common.log.error(common.err('Invalid cast externalized: ' + v.slot,
                                    'frost:invalid_cast'));
      }
    });
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

  common.method(that, 'receive', receive, _super);
  common.method(that, 'send', send, _super);

  init();

  return that;
};

exports.frost = frost;
