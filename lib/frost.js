/**
 * frost: frost.js
 *
 * Copyright (c) 2014, Stanislas Polu. All rights reserved.
 *
 * @author: spolu
 *
 * @log:
 * - 2014-09-26 spolu   Slot reclamation
 * - 2014-09-25 spolu   Protocol definition
 * - 2014-09-19 spolu   Creation
 */
"use strict"

var common = require('./common.js');
var events = require('events');
var ed25519 = require('ed25519');

var protocol = require('fba').protocol;
var node = require('fba').node;
var message = require('fba').message;

// ## frost
//
// ```
// @spec  { public_key, private_key,
//          verifier, acceptor }
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

  my.receivers = {};

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

  var def_verifier;      /* def_verifier(from, channel, payload); */
  var def_acceptor;      /* def_acceptor(from, channel, payload); */

  var init;              /* init(); */

  //
  // ### _that_
  //
  var that = new events.EventEmitter();

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

      if(!my.verifier(from, channel, cast.pay)) {
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

      if(!my.acceptor(from, channel, cast.pay)) {
        return false;
      }
    }
    catch(err) {
      return false;
    }

    return true;
  };

  // ### def_verifier
  //
  // Default verifier. Called at ballot verification if no verifier is
  // specified. Defining a verifier allows to the implementor to check the
  // validity of a message before it is even considered for processing.
  //
  // This can be used to filter out messages illegally sent on invalid channels
  // for the sender. This will prevent the node from accepting this message
  // even if its peers externalize it.
  //
  // ```
  // @from    {string} sender public key
  // @channel {string} the channel on which the message is sent
  // @payload {object} the message payload
  // ```
  def_verifier = function(from, channel, payload) {
    return true;
  };

  // ### def_acceptor
  //
  // Default acceptor. Called at ballot acceptance if no acceptor is
  // specified. Defining an acceptor allows to the implementor to check the
  // possibility to pledge for that message. Even if the acceptor refuses the
  // message, the message can be externalized if the rest of the peers
  // externalize it.
  //
  // ```
  // @from    {string} sender public key
  // @channel {string} the channel on which the message is sent
  // @payload {object} the message payload
  // ```
  def_acceptor = function(from, channel, payload) {
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
  // @cb_        {function(err)}
  // ```
  peer_connect = function(url, public_key, cb_) {
    var ws = new (require('ws'))(url);

    ws.on('error', function(err) {
      that.emit('peer_error', {
        error: err,
        public_key: public_key,
        url: url
      });
      if(cb_) {
        cb_(err);
        cb_ = null;
      }
    });
    ws.on('close', function(err) {
      that.emit('peer_close', {
        public_key: public_key,
        url: url
      });
      /* TODO(spolu) reconnect? delete? */
    });
    ws.on('open', function() {
      that.emit('peer_open', {
        public_key: public_key,
        url: url
      });
      if(cb_) {
        cb_();
        cb_ = null;
      }
    });
    ws.on('message', handle_message);

    my.peers[public_key] = {
      public_key: public_key,
      url: url,
      ws: ws
    };
    my.node.quorums().add_node(public_key);

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
      my.node.quorums().remove_node(public_key);
    };
    return that;
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
    my.receivers[channel] = my.receivers[channel] || [];
    my.receivers[channel].push(cb_);
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
    if(channel.indexOf(':') !== -1) {
      return cb_(common.err('Invalid channel: ' + channel,
                            'frost:invalid_channel'));
    }
    var from = my.node.public_key();

    if(!my.casts[channel]) {
      my.casts[channel] = {};
    }
    if(!my.casts[channel][from]) {
      my.casts[channel][from] = {
        sha: '',
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
    var slot = channel + ':' + from + ':' + cast.sha;

    /* We don't need to update `my.casts` here as it will be done by the */
    /* protocol `value` event handler.                                   */
    my.protocol.request(slot, JSON.stringify(cast), 2000, function(err, value) {
      if(err) {
        return cb_(err);
      }
      try {
        var c = JSON.parse(value)
        return cb_(null, c.sha);
      }
      catch(err) {
        return cb_(err);
      }
    });
  };

  // ### init
  //
  // Initializes the object once it's fully constructed
  init = function() {
    my.verifier = spec.verifier || def_verifier;
    my.acceptor = spec.acceptor || def_acceptor;

    my.node = node({
      public_key: spec.public_key,
      private_key: spec.private_key
    });
    my.protocol = protocol({ 
      node: my.node,
      ballot_generator: ballot_generator,
      ballot_verifier: ballot_verifier,
      ballot_acceptor: ballot_acceptor
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
        if(verify_cast(from, channel, cast)) {
          if(!my.casts[channel]) {
            my.casts[channel] = {};
          }
          /* We reclaim the previous slot to keep only most recent casts' */
          /* slots active.                                                */
          if(my.casts[channel][from]) {
            var prev_slot = channel + ':' + from + ':' + 
              my.casts[channel][from].sha;
            my.protocol.reclaim(prev_slot);
          }
          my.casts[channel][from] = cast;

          process.nextTick(function() {
            (my.receivers[channel] || []).forEach(function(cb_) {
              return cb_(from, cast.sha, cast.pay);
            });
          });
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

  common.method(that, 'listen', listen, _super);

  common.method(that, 'receive', receive, _super);
  common.method(that, 'send', send, _super);

  common.getter(that, 'node', my, 'node');

  init();

  return that;
};

exports.frost = frost;
