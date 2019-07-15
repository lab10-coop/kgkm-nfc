const Web3 = require('web3');
const web3s2g = require('./web3-s2g.js');

let log_debug_signing = true;

function toHex(nonHex, prefix = true) {
  let temp = nonHex.toString('hex');
  if (prefix) {
    temp = `0x${temp}`;
  }
  return temp;
}

const web3 = new Web3('wss://ws.sigma1.artis.network');

const rawTxOpen = {
 // nonce: '0x00',
  gasPrice: 100000000000,
  to: '0xE53BA69C94b657838B2b22B9BC609163cC34512f',
  value: 0,
  data: '0x0905186e00000000000000000000000001019e15b7beef611ac4659e7acdc272c4d90afa00000000000000000000000000000000000000000000000000000a86cc92e3da',
  gasLimit: '0x100000'
};

const rawTxClose = {
 // nonce: '0x00',
  gasPrice: 100000000000,
  to: '0xE53BA69C94b657838B2b22B9BC609163cC34512f',
  value: 0,
  data: '0x9abe837900000000000000000000000001019e15b7beef611ac4659e7acdc272c4d90afa',
  gasLimit: '0x100000'
};


let txOpen = null;
let txClose = null;


async function putCard(reader) {


  logSigning('putCard');
  // create both transactions

  var card = new web3s2g.Security2GoCard(reader);
 
  var closeNonce = await web3.eth.getTransactionCount(await card.getAddress(1));

  txOpen = await card.signTransaction(web3,rawTxOpen, 1);
  txClose =  await card.signTransaction(web3,rawTxClose, 1, closeNonce + 1);

  //console.log(txClose);
  // send open
  sendSignedTransaction(txOpen);
}

function takeCard() {

  if (txClose != null) {
    console.log('takeCard');
    // send close
    sendSignedTransaction(txClose);
  }
}

async function sendSignedTransaction(tx) {

  try {
    const receipt = await web3.eth.sendSignedTransaction(tx);
    console.log(`transaction receipted, hash: ${receipt.transactionHash}`);
    
  } catch (error) {
    console.log('caught exception: ' + error);
  }
  
  //todo: handle errors, and pseudo errors in a better way.
}

function logSigning(message) {
  if (log_debug_signing) {
    console.log(message)
  }
}

module.exports = {
  takeCard,
  putCard
}
