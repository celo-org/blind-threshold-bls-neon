const Benchmark = require('benchmark');
const suite = new Benchmark.Suite;

// Import the library
const threshold = require('../native');
const util = require('util');

// Get a message and a secret for the user
const msg = Buffer.from("hello world")
const userSeed = Buffer.from('d3760f2338e13b3eb5ffd6203e5381be37ba93b5dc89c0431738d9dbfaeacfb7', 'hex')

// Blind the message
const blinded = threshold.blind(msg, userSeed)
const blindedMessage = blinded.message

const t = 3;
const n = 4;

const keys = [
Buffer.from('00000000e814cbd163943dc5ca27ef5674ffc5216d949ea7bc3f1ff521d2c329b1454e0f', 'hex'),
Buffer.from('010000003ce2f3d1940984937b39457aa7edab6da589a64410b44258cc182592b59cb811', 'hex'),
Buffer.from('02000000ff18dc2ff0d9abf3b5ac28a6c0a169167c4fd5060aa30590410caf33acc35d06', 'hex'),
Buffer.from('0300000033b983eb7505d8f97b81997abd0954cff3459aa6e6a6d05d2ef7ba4252859412', 'hex'),
];

const polynomial = Buffer.from('0300000000000000b77fc3d46bd751450675de86b2aa65fdb6b7e2ae272e84b3e3da209088a6f5456bad2746be13ce81e7b7f0eba3df6501b06377f1cce1e93a6c8c1699222acb92cf9f5d3180170d70aa109435570187bcd697a8baeac24fa30ef6491c8eede600ee929b615a4a2399e02e9a18c0863435dc89b9c29d9ae276b3e1f61ed05e55fe2673a53e3b9fc03e038b8ad165b05a01817ad0fbd04442b895f826f07196c9757ce7a31b6dc76b9005ccc16867da6114d7c8be22d6496100de536f4f4ef7f980170d13c7ada37d1c2e239e03efb7a69b09d0be908d31916f49967b0894428ea774d47d514576ef183634c14033beba00d79762a88e0e81fe6ab3448f585a6acb7e6aa38fed8576a5f78626bbc9073c08f3c4ff2262a9fda42328fe1c5668fb00', 'hex')

// each of these shares proceed to sign teh blinded sig
let sigs = []
for (let i = 0 ; i < n; i++ ) {
    const sig = threshold.partialSignBlindedMessage(keys[i], blindedMessage)
    sigs.push(sig)
}

// add tests
suite.add('sign blind', function() {
	threshold.partialSignBlindedMessage(keys[0], blindedMessage)
})
suite.add('partial verify', function() {
    	threshold.partialVerifyBlindSignature(polynomial, blindedMessage, sigs[0])
})
suite.add('combine', function() {
	threshold.combine(t, flattenSigsArray(sigs))
})
.on('cycle', function(event) {
  console.log(String(event.target));
})
// run async
.run({ 'async': true });

function flattenSigsArray(sigs) {
    return Uint8Array.from(sigs.reduce(function(a, b){
      return Array.from(a).concat(Array.from(b));
    }, []));
}


