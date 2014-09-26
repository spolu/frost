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

  my.node = node({
    public_key: spec.public_key,
    private_key: spec.private_key
  });
  my.protocol = protocol({ node: my.node });
  my.wss = null;

  my.queries = {};
  my.QRY_TIMEOUT = 1000;

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
  var handle_qry;        /* handle_qry(msg); */
  var handle_lst;        /* handle_lst(msg); */

  //
  // ### _that_
  //
  var that = {};

  /****************************************************************************/
  /* PRIVATE HELPERS */
  /****************************************************************************/
  // ### handle_fba
  //
  // Handles a message of type `fba` (participating in the core FBA protocol)
  // ```
  // @msg {object} the message json
  // ```
  handle_fba = function(msg) {
    var m = message({}).from_json(msg.m);
    my.protocol.process(m);
  };

  // ### handle_qry
  //
  // Handles a `qry` message which encodes a query that should be forwarded
  // along peers until it is responded
  //
  // The message has the following format:
  // ```
  //  t: 'qry'
  //  q: the query string
  //  f: the node from which it was issued
  //  s: the signature of the query string
  // ```
  // ```
  // @msg {object} the mesage json
  // @ws  {object} the websocket to use
  // ```
  handle_qry = function(msg, ws) {
    if(!ed25519.Verify(new Buffer(common.hash([msg.q]), 'utf8'), 
                       new Buffer(msg.s, 'base64'),
                       msg.f)) {
      common.log.error(common.err('Signature verification failed: ' + msg.s,
                                  'frost:sign_fail'));
      return;
    }

    /* TODO handle query */
    var r = '';

    var private_key = new Buffer(my.node.private_key(), 'base64')
    var signature = ed25519.Sign(new Buffer(common.hash([r, msg.f]), 'utf8'), 
                                 private_key).toString('base64');
    var msg = {
      t: 'rsp',
      q: msg.f,
      r: r,
      f: my.node.public_key(),
      s: signature
    };
    ws.send(JSON.stringify(msg));
  };

  // ### handle_rsp
  //
  // Handles a `rsp` message which encodes a response to a query
  //
  // The message has the following format:
  // ```
  // t: 'rsp'
  // q: the original query signature
  // r: the response string
  // f: the node from which this response is issued
  // s: the signature of the response string & query signature
  // ```
  // ```
  // @msg {object} the message json
  // ```
  handle_rsp = function(msg) {
    if(!ed25519.Verify(new Buffer(common.hash([msg.r, msg.q]), 'utf8'), 
                       new Buffer(msg.s, 'base64'),
                       msg.f)) {
      common.log.error(common.err('Signature verification failed: ' + msg.s,
                                  'frost:sign_fail'));
      return;
    }

    if(my.queries[msg.q]) {
      var cb_ = my.queries[msg.q].cb_;
      delete my.queries[msg.q];
      return cb_(null, r);
    }

  };
  

  // ### send_qry
  //
  // Generates and send a `qry` message. The callback is called once the query
  // is replied or a timeout occurred
  // ```
  // @pk  {string} peer public key
  // @q   {string} query string
  // @cb_ {function(err, rsp)}
  // ```
  send_qry = function(pk, q, cb_) {
    var private_key = new Buffer(my.node.private_key(), 'base64')
    var signature = ed25519.Sign(new Buffer(common.hash([q]), 'utf8'), 
                                 private_key).toString('base64');
    var msg = {
      t: 'qry',
      q: q,
      f: my.node.public_key(),
      s: signature
    };

    if(!my.peers[pk]) {
      return cb_(common.err('Peer unknown: ' + pk,
                            'frost:peer_unknown'));
    }

    my.queries[msg.s] = {
      msg: msg,
      cb_: cb_
    };
    my.peers[pk].ws.send(JSON.stringify(msg));

    setTimeout(function() {
      if(my.queries[msg.s]) {
        delete my.queries[msg.s];
      }
      return cb_(common.err('Query timed out: ' + q,
                            'frost:query_timeout'));
    }, my.QRY_TIMEOUT);
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
    ws.on('message', function(data, flags) {
      /* TODO(spolu) */
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
      ws.on('message', function(data) {
        try {
          var msg = JSON.parse(data);
          if(msg.t === 'fba') {
            handle_fba(msg);
          }
          if(msg.t === 'qry') {
            handle_qry(msg, ws);
          }
        }
        catch(err) {
          common.log.error(common.err('Parsing failed',
                                      'frost:parse_fail'));
        }
      });
      //ws.send('something');
    });

    return that;
  };

  // ### receive
  //
  // Listens to the specified channel for messages
  // ```
  // @channel {string} the channel name
  // @cb_     {function(sequence, sha, payload)} callback with received message
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
  // @cb_      {function(err, sequence, sha)} callback with eventual error
  // ```
  send = function(channel, payload, cb_) {
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

  return that;
};

exports.frost = frost;
