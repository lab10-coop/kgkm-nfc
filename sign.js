const Tx = require('ethereumjs-tx');
const Util = require('ethereumjs-util');
const Web3 = require('web3');
const s2go = require('./wrapper');

let log_debug_signing = true;

function toHex(nonHex, prefix = true) {
  let temp = nonHex.toString('hex');
  if (prefix) {
    temp = `0x${temp}`;
  }
  return temp;
}


async function sign(web3, rawTx, secondTx) {
  const wrapper = new s2go.security2goWrapper();
  const publickey = await wrapper.getPublicKey(1);
  logSigning('publickey');
  logSigning(publickey);


  // get address from publickey
  let address = '0x' + web3.utils.sha3('0x' + publickey).slice(26);
  logSigning('address');
  logSigning(address);

  if (!secondTx) {
    rawTx.nonce = await web3.eth.getTransactionCount(address);
  } else {
    rawTx.nonce = (await web3.eth.getTransactionCount(address)) + 1;
  }
  // todo: is the nonce in 0x hex format?
  logSigning('rawTx.nonce');
  logSigning(rawTx.nonce);

  const tx = new Tx(rawTx);
  //tx.sign(privateKey);

  const hash = toHex(tx.hash(false), false);
  logSigning('hash');
  logSigning(hash);


  let serializedTx = '';
  let i = 0;
  do {
    logSigning('tries to generate signature.');

    const cardSig = await wrapper.generateSignature(1, hash.toString('hex'));
    logSigning('cardSig');
    logSigning(cardSig);

    let rStart = 6;
    let length = 2;
    const rLength = parseInt(cardSig.slice(rStart, rStart + length), 16);
    logSigning('rLength');
    logSigning(rLength);
    rStart += 2;
    const r = cardSig.slice(rStart, rStart + rLength * 2);
    logSigning('r');
    logSigning(r);

    let sStart = rStart + rLength * 2 + 2;
    const sLength = parseInt(cardSig.slice(sStart, sStart + length), 16);
    logSigning('sLength');
    logSigning(sLength);
    sStart += 2;
    const s = cardSig.slice(sStart, sStart + sLength * 2);
    logSigning('s');
    logSigning(s);

    rawTx.r = '0x' + r;
    rawTx.s = '0x' + s;

    const tx2 = new Tx(rawTx);
    //logSigning(tx2);

    serializedTx = tx2.serialize();
    logSigning('serializedTx');
    logSigning(toHex(serializedTx));
    logSigning(web3.eth.accounts.recoverTransaction(toHex(serializedTx)));

    i += 1;
  } while (web3.eth.accounts.recoverTransaction(toHex(serializedTx)).toLocaleLowerCase() !== address);

  console.log(`trys: ${i}`);

  return toHex(serializedTx);
}

const web3 = new Web3('wss://ws.sigma1.artis.network');

const rawTxOpen = {
 // nonce: '0x00',
  gasPrice: 1000000000,
  to: '0xE53BA69C94b657838B2b22B9BC609163cC34512f',
  value: 0,
  data: '0x0905186e00000000000000000000000001019e15b7beef611ac4659e7acdc272c4d90afa00000000000000000000000000000000000000000000000000000a86cc92e3da',
  gasLimit: '0x100000'
};

const rawTxClose = {
 // nonce: '0x00',
  gasPrice: 1000000000,
  to: '0xE53BA69C94b657838B2b22B9BC609163cC34512f',
  value: 0,
  data: '0x9abe837900000000000000000000000001019e15b7beef611ac4659e7acdc272c4d90afa',
  gasLimit: '0x100000'
};


let txOpen = null;
let txClose = null;


async function putCard() {
  logSigning('putCard');
  // create both transactions

  txOpen = await sign(web3, rawTxOpen);
  txClose = await sign(web3, rawTxClose, true);

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

async function start() {
  await putCard();
  await takeCard();

  //const tx = await sign(web3, rawTxOpen);
  //const tx = await sign(web3, rawTxClose);
  //await web3.eth.sendSignedTransaction(tx).on('receipt', console.log);
}

//start();


module.exports = {
  takeCard,
  putCard
}
