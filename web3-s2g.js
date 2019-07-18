/**
* @file Web3 Security2Go
* @author Thomas Haller <thomas.haller@lab10.coop>
* @version 0.1
*/

const web3utils = require('web3-utils');
const util = require('util');
const Tx = require('ethereumjs-tx');
const utils = require('ethereumjs-util');

function toHex(nonHex, prefix = true) {
  let temp = nonHex.toString('hex');
  if (prefix) {
    temp = `0x${temp}`;
  }
  return temp;
}

function toHexString(byteArray) {
  let s = '0x';
  byteArray.forEach((byte) => {
    s += (`0${(byte & 0xFF).toString(16)}`).slice(-2);
  });
  return s;
}

function isError(code) {
  if (code[0] === 0x90 && code[1] === 0) { return false; }
  return true;
}


/**
 *
 * @param {byte[]} errorCode byte array with the error information at position 0 and zero
 * @returns {string} error message
 */
function getGenericErrorAsString(errorCode) {
  // todo: maybe thread the error codes in lookup tables ?
  // that would make it easier to distinguish between generic and specific errors.

  // success is not an error. please check for success state before.
  if (errorCode[0] === 0x90 && errorCode[1] === 0) { return 'Success'; }
  if (errorCode[0] === 0x64) { return `Operation failed (${errorCode[1]})`; }
  if (errorCode[0] === 0x67 && errorCode[1] === 0) { return 'Wrong length'; }
  if (errorCode[0] === 0x69) {
    if (errorCode[1] === 0x82) { return 'Global or key-specific signature counter exceeded'; }
  }
  if (errorCode[0] === 0x6A) {
    if (errorCode[1] === 0x86) { return 'Incorrect parameters P1/P2'; }
    // this is NOT documented as a "Generic Error" but for now it seems to be safe to thread it like this.
    if (errorCode[1] === 0x88) { return 'Key slot with given index is not available'; }
  }
  if (errorCode[0] === 0x6D && errorCode[1] === 0) {
    return 'Instruction code is not supported or invalid or application has not selected with the SELECT APP command';
  }
  if (errorCode[0] === 0x6E && errorCode[1] === 0) { return 'Class not supported'; }
  if (errorCode[0] === 0x6F && errorCode[1] === 0) { return 'Unknown Error'; }

  function InttoHex(d) {
    return (`0${Number(d).toString(16)}`).slice(-2).toUpperCase();
  }

  return `ErrorCode Unknown:${InttoHex(errorCode[0])} ${InttoHex(errorCode[1])}`;
}

function parseSelectAppResponse(response) {
  const result = {
    pinActivationStatus: 0,
    cardID: '',
    versionStringRaw: '',
    versionString: '',
    successRaw: '',
    success: true,
    errorString: '',
  };

  if (response.length === 2) {
    result.success = false;
    getGenericErrorAsString(response);
    result.errorString();
  } else if (response.length === 20) {
    const pinActivationStatusByte = response[0];
    result.pinActivationStatus = pinActivationStatusByte;
    result.cardID = response.slice(1, 11);
    result.versionStringRaw = response.slice(11, 18);
    result.versionString = result.versionStringRaw.toString('ascii');

    const responseSuccess = response.slice(19, 20);

    if (responseSuccess[0] === 0x90 && responseSuccess[1] === 0x0) {
      result.success = true;
    } else {
      // according to S2G documentation that else should never hit.
      result.success = false;
      result.errorString = getGenericErrorAsString(responseSuccess);
    }
    // result.pinActivationStatus = response[0];
  } else if (response.length === 14) {
    // TODO:
    // according to Documentation, SELECT APP response should be 20 bytes, but is 14.
    console.log(toHexString(response));
  } else {
    throw Error(`unexpected SelectAppResponse length: ${response.length}`);
  }

  return result;
}

/**
* Sends raw byte commands to the card and receives the response.
* sends the always required SelectApp command in advance.
*
* @param {Security2GoCard} card object
* @param {byte[]} bytes raw byte[] with the netto data.
* @param {receiveHandler} callback once the operation is finished.
*/
function sendCommand(card, bytes, receiveHandler = null) {
  const maxResponseLength = 128;
  card.logSigning('connecting...');
  card.reader.connect({}, (errConnect, protocolConnnected) => {
    if (errConnect) {
      console.error(`Connecting Error:${errConnect}`);
    } else {
      let protocol = protocolConnnected;
      if (protocol === undefined) {
        protocol = card.PROTOCOL_ID;
      }
      card.logSigning(`protocol:${protocol}`);
      const selectAppIncldingCommand = [0x00, 0xA4, 0x04, 0x00, 0x0D, /* start of body */
        0xD2, 0x76, 0x00, 0x00, 0x04, 0x15, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 /* end of body */, 12];
      card.reader.transmit(
        Buffer.from(selectAppIncldingCommand), maxResponseLength, protocol,
        (errSelectAppTransmit, dataSelectAppTransmit) => {
          card.logSigning('select App Completed');
          if (errSelectAppTransmit) {
            console.error(errSelectAppTransmit);
          } else {
            const selectAppResponse = parseSelectAppResponse(dataSelectAppTransmit);
            card.logSigning(`SelectApp result: ${JSON.stringify(selectAppResponse)} `);
            // todo: validate result.
            card.reader.transmit(Buffer.from(bytes), maxResponseLength, protocol, (err, dataTransmit) => {
              if (err) {
              // todo: interprate error here ?
                card.logSigning('Error on transmitting');
                card.logSigning(err);
                return [];
              }
              card.logSigning('Data received', dataTransmit);

              // asume all 2 byte results are errors ?!
              if (dataTransmit.length === 2 && isError(dataTransmit)) {
                const errorMsg = getGenericErrorAsString(dataTransmit);
                console.error(`Received Data is Error received: ${errorMsg}`);
                throw errorMsg;
              }

              card.logSigning(receiveHandler);
              // reader.close();
              // pcsc.close();
              if (receiveHandler != null) {
                receiveHandler(dataTransmit);
              }
              return true;
            });
          }
        },
      );
    }
  });
}

async function generateSignatureRaw(card, bytes, keyIndex) {
  function generateSignatureRawFunction(args, callback) {
    // const { bytes } = args;
    // const { keyIndex } = args;
    // const { card } = args;


    if (bytes.length !== 32) {
      const error = `message to sign needs to be 32 byte long. got:${bytes.length}`;
      card.logSigning(error);
      throw error;
    }

    const messageBuffer = new ArrayBuffer(38);
    const messageBufferView = new Int8Array(messageBuffer);

    messageBufferView[1] = 0x18;
    messageBufferView[2] = keyIndex;
    messageBufferView[3] = 0x00;
    messageBufferView[4] = 0x20;
    messageBufferView.set(bytes, 5);

    card.logSigning(`signing: ${toHexString(messageBufferView)}`);
    sendCommand(card, messageBuffer, (sendCommandResponse, error) => {
      if (sendCommandResponse) {
        card.logSigning(`Signing: Got Response: ${toHexString(sendCommandResponse)}`);
        if (sendCommandResponse[sendCommandResponse.length - 2] === 0x90
            && sendCommandResponse[sendCommandResponse.length - 1] === 0) {
          card.logSigning('card Signature is a success!');
          // todo:
          const resultBin = sendCommandResponse.slice(9, sendCommandResponse.length - 2);
          const result = web3utils.bytesToHex(resultBin);
          callback(null, result);
          return;
        }
        console.error(`Signing: not implmented signing response:${toHexString(sendCommandResponse)}`);
      }
      if (error) {
        console.error(`Signing Error: ${error}`);
        callback(error, null);
      }
    });
  }

  const func = util.promisify(generateSignatureRawFunction);
  return func({ card, bytes, keyIndex });
}

class Security2GoCard {
  /**
     * Represents an Infinion Security2Go played on a card reader using the pcsclite framework.
     *
     * @param {pcsclite.CardReader} reader a CardReader from pcsclite.
     */
  constructor(reader) {
    this.reader = reader;
    // todo: in our case protocol was allways 2. sometimes reader.connect() delievers a protocol number, sometimes not
    // this is a very uncool workaround for this problem.
    this.PROTOCOL_ID = 2;
    this.log_debug_signing = false;
    this.log_debug_web3 = false;
  }

  /**
    * returns the publicKey of the given index of the card.
    * for retrieving the (ethereum) address call getAddress(keyIndex)
    * @param {byte} cardKeyIndex
    * index (0..255) of the Security2Go Card.  defaults to 1 (first generated key on the card)
    * @return {string} public key
    */
  async getPublicKey(cardKeyIndex = 1) {
    function getPublicKeyFunction(args, callback) {
      const { card } = args;
      sendCommand(card, args.command, (response) => {
        if (response.length === 2) {
          if (response[0] === 0x69) {
            if (response[1] === 82) {
              card.logSigning('Maximal number of key import calls exceeded (Security status not satisfied)');
            } else if (response[1] === 85) {
              card.logSigning('Not authenticated with PIN (Condition of use not satisfied)');
            }
          }
          if (response[0] === 0x6a && response[1] === 0x88) {
            card.logSigning('Key slot with given index is not available');
          }
        } else if (response.length === 75) {
          // var sec1EncodedPublicKey =  response.slice(8, 64);
          // card.logSigning('response: ' + response);
          card.logSigning(`result_code: ${response[73]} ${response[74]}`);
          // card.logSigning('Public key:' + keyIndex + ':' + toHexString(publicKey));
          const buffer = response.slice(9, 64 + 9);
          // var bufferHex = toHexString(buffer);
          callback(null, buffer);
        } else {
          card.logSigning(`Unknown response: length: ${response.length} - ${response}`);
        }
      });
    }
    const card = this;
    card.logSigning(`getting key #${cardKeyIndex}`);
    const command = [0x00, 0x16, cardKeyIndex, 0x00, 0x00];

    card.logSigning('response');
    // card.logSigning(responseFunction);


    const func = util.promisify(getPublicKeyFunction);

    return func({ card: this, command });
    // card.logSigning(responseFunction);
    // return new Promise(resolve => {});
  }

  /**
    * returns the (ethereum) address of the given index of the card.
    * for retrieving the raw public key call getPublicKey(keyIndex)
    * @param {byte} keyIndex index (0..255) of the Security2Go Card. defaults to 1 (first generated key on the card)
    * @return {string} public key
    */
  async getAddress(keyCardIndex = 1) {
    const publicKey = await this.getPublicKey(keyCardIndex);
    const publicKeyHex = web3utils.bytesToHex(publicKey);
    this.logSigning('publicKeyHex:');
    this.logSigning(publicKeyHex);
    const address = `0x${web3utils.sha3(publicKeyHex).slice(26)}`;
    this.logSigning('address');
    this.logSigning(address);
    return address;
  }


  /**
    * Generates a signature for a given web3 style transaction
    * @param {Web3} web3 a Web3 instance.
    * @param {*} rawTransaction a Web3 style transaction.
    * @param {byte} cardKeyIndex keyIndex index (0..255) of the Security2Go Card.
    * defaults to 1 (first generated key on the card)
    */
  async signTransaction(web3, rawTransaction, cardKeyIndex = 1) {
    const tx = await this.getSignedTransactionObject(web3, rawTransaction, cardKeyIndex);
    return toHex(tx.serialize());
  }

  /**
    * Generates a ethereum compatible secp256k1 signature for the given hash
    * @param {string} hashString hex encoded hash string.
    * @param {byte} cardKeyIndex keyIndex index (0..255) of the Security2Go Card.
    * defaults to 1 (first generated key on the card)
    */
  async getSignatureFromHash(hashString, cardKeyIndex = 1) {
    let hash = hashString;
    let hashBytes;

    if (typeof hash === 'string') {
      if (hash.startsWith('0x')) {
        hash = hash.substring(2, hash.length);
      }
      hashBytes = Buffer.from(hash, 'hex');
    } else {
      hashBytes = hash;
    }

    this.logSigning(`hash:${hash}`);
    this.logSigning(`buffer.length: ${hashBytes.length}`);

    const cardSig = await generateSignatureRaw(this, hashBytes, cardKeyIndex);

    this.logSigning('tries to generate signature.');

    // const cardSig = await wrapper.generateSignature(1, hash.toString('hex'));

    this.logSigning('cardSig');
    this.logSigning(cardSig);

    let rStart = 6;
    const length = 2;
    const rLength = parseInt(cardSig.slice(rStart, rStart + length), 16);
    this.logSigning('rLength');
    this.logSigning(rLength);
    rStart += 2;
    const r = cardSig.slice(rStart, rStart + rLength * 2);
    this.logSigning('r');
    this.logSigning(r);
    console.assert(r.length === rLength * 2, `r should be length ${rLength * 2} but has length ${r.length}`);

    let sStart = rStart + rLength * 2 + 2;
    const sLength = parseInt(cardSig.slice(sStart, sStart + length), 16);
    this.logSigning('sLength');
    this.logSigning(sLength);

    sStart += 2;
    const s = cardSig.slice(sStart, sStart + sLength * 2);

    this.logSigning('s');
    this.logSigning(s);
    console.assert(s.length === sLength * 2, `s should be length ${sLength * 2} but has length ${s.length}`);

    const result = {
      r: `0x${r}`,
      s: `0x${s}`,
    };

    const correctPublicKey = await this.getPublicKey(cardKeyIndex);


    function isAddressMatching(testingVvalue) {
      const pubKey = utils.ecrecover(hashBytes, testingVvalue, result.r, result.s);

      // console.log('comparing public key');
      // console.log(pubKey);
      // console.log(correctPublicKey);
      return correctPublicKey.equals(pubKey);
    }

    if (isAddressMatching('0x1b')) {
      result.v = '0x1b';
    } else if (isAddressMatching('0x1c')) {
      result.v = '0x1c';
    } else {
      throw Error('unable to determine correct v value');
    }

    return result;
  }

  /**
    * Generates an EthereumTx transaction object that includes the signature as R,S,V components.
    * @param {Web3} web3 a Web3 instance.
    * @param {*} rawTransaction a Web3 style transaction.
    * @param {byte} cardKeyIndex keyIndex index (0..255) of the Security2Go Card.
    * defaults to 1 (first generated key on the card)
    */
  async getSignedTransactionObject(web3, rawTransaction, cardKeyIndex = 1) {
    const address = await this.getAddress(cardKeyIndex);
    this.logSigning('address');
    this.logSigning(address);

    console.log(`rawTransaction: ${JSON.stringify(rawTransaction)}`);

    const transaction = JSON.parse(JSON.stringify(rawTransaction));

    if (!transaction.nonce) {
      transaction.nonce = await web3.eth.getTransactionCount(address);
    }

    console.log(`tx: ${JSON.stringify(transaction)}`);

    const tx = new Tx(transaction);

    const hashBytes = tx.hash(false);
    const hash = toHex(hashBytes, false);
    this.logSigning('hash');
    this.logSigning(hash);


    let serializedTx = '';


    const rsSig = await this.getSignatureFromHash(hash, cardKeyIndex);
    tx.r = rsSig.r;
    tx.s = rsSig.s;
    tx.v = rsSig.v;

    // console.log('v: ' + tx2.v);
    serializedTx = toHex(tx.serialize());
    this.logSigning('serializedTx');
    this.logSigning(serializedTx);
    // card.logSigning('tx2.v', toHex(tx2.v));
    // this.logSigning(web3.eth.accounts.recoverTransaction(toHex(serializedTx)));


    this.logSigning(`tx: ${JSON.stringify(tx, null, 2)}`);


    // if (rLength  != tx.r.length) {
    //     console.error(`wrong R length - expecting this to fail rLength ${rLength} tx.r.length ${tx.r.length}`);
    // }

    // if (sLength != tx.s.length) {
    //     console.error(`wrong S length - expecting this to fail ${sLength} tx.s.length ${tx.s.length}`);
    // }

    this.logSigning(`serialized transaction:${serializedTx}`);
    return tx;
  }


  /**
     * @param {Web3} web3 a Web3 instance
     * @param {object} web3 transaction tx
     * @param {number} cardKeyIndex keyIndex index (0..255) of the Security2Go Card
     * @throws {*} error from sendSignedTransaction
     * @return {receipt} the web3 receipt
     */
  async signAndSendTransaction(web3, tx, cardKeyIndex = 1) {
    const signature = await this.signTransaction(web3, tx, cardKeyIndex);

    this.logWeb3(`tx: ${JSON.stringify(tx, null, 2)}`);

    try {
      this.logWeb3('sending transaction');
      const txReceipt = await web3.eth.sendSignedTransaction(signature);
      this.logWeb3(`receipt: ${txReceipt}`);
      return txReceipt;
    } catch (error) {
      // the following error occurs all the time.
      // Error: Transaction has been reverted by the EVM:
      // no idea why yet....
      console.error('Error:', error);
      throw error;
    }
  }

  /**
     * console.log() if log_debug_web3
     * @param {*} message
     */
  logWeb3(message) {
    if (this.log_debug_web3) {
      console.log(message);
    }
  }

  /**
     * console.log() if log_debug_signing
     * @param {*} message
     */
  logSigning(message) {
    if (this.log_debug_signing) {
      console.log(message);
    }
  }
}

module.exports = {
  Security2GoCard,
};
