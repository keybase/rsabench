'use strict';

// fake console log for debugging
var console;
if (!console) {
  console = {
    log: function(message) {
      self.postMessage({
        request: 'log',
        message: Array.prototype.slice.call(arguments)
      });
    }
  };
}

// JSBN
importScripts("jsbn/jsbn.js", "jsbn/jsbn2.js", "jsbn/prng4.js", "jsbn/rng.js", "jsbn/rsa.js",
  "jsbn/rsa2.js");

// Forge
var window = {};  // hack so Forge will load
importScripts("forge/asn1.js", "forge/oids.js", "forge/aes.js", "forge/prng.js", "forge/sha1.js",
  "forge/util.js", "forge/random.js", "forge/rsa.js", "forge/pki.js");

importScripts("keybase.js");

function runBench(bits, count, generator) {
  var raw = [];
  for (var i = 0; i < count; i++) {
    var before = new Date();
    var output = generator(bits);
    var after = new Date();
    var time = (after - before);
    raw.push(time);
  }
  return raw;
}

function generateJsbn(bits) {
  var key = new RSAKey();
  key.generate(bits, "10001");
  return key;
}

function run_keybase (e, self) {
   var raw = [];
   var i = 0;
   var run = function () {
     if (i < e.data.count) {
       self.postMessage({type:'response', data: raw});
     } else {
       i++;
       var before = new Date();
       keybase.RSA.generate({nbits : e.data.bits}, function () {
         var after = new Date();
         var time = after - before;
         raw.push(time);
       });
    }
  }
};

self.addEventListener('message', function(e) {
  var generator = null;
  if (e.data.type == 'jsbn') {
    generator = generateJsbn;
  } else if (e.data.type == 'forge') {
    generator = forge.pki.rsa.generateKeyPair;
  } else if (e.data.type == 'keybase') {
    run_keybase(e, self);
    return;
  } else {
    self.postMessage({type: 'error', message: 'unknown type: ' + e.data.type});
  }

  if (generator !== null) {
    var data = runBench(e.data.bits, e.data.count, generator);
    self.postMessage({type:'response', data: data});
  }
}, false);
