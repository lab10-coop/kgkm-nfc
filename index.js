
var Pcsc = require('@pokusew/pcsclite');
const sign = require('./sign');

const util = require('util');
const exec = util.promisify(require('child_process').exec);

const web3s2g = require('./web3-s2g.js');

// testcode: runable with "node ."

// async function test()
// {
//     var wrapper = new security2goWrapper();
//     let publickey = await wrapper.getPublicKey(1);
//     console.log('publickey: ' + publickey);
//     let signature = await wrapper.generateSignature(1, "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
//     console.log('signature: ' + signature);
// }

//const delay = ms => new Promise(res => setTimeout(res, ms));
//await delay(5000);

const pcsc = Pcsc();

//const SCARD_STATE_EMPTY = ;
let lastStateWasCard = false;

let lastDetectedReader = false;

let isShuttingDown = false;

//this are known cards, that can be used to shut down the system.
//this is usefull because the GEMBird EG-PM2 stores the state of the power sockets
//and the raspberry pi has no "shutdown" button.
//therefore we use this card to shutdown the system.
const terminatorCards = {
    "0x756269ce7e0285670ecbd234f230645efba049d3" : true,
    "0x0774fe042bc23d01599b5a92b97b3125a4cb20ee" : true
}


const delay = ms => new Promise(res => setTimeout(res, ms));

async function switchPortOn(portNumber) {
    if (isShuttingDown) {
        //we do not like to switch any port on in the case we are allready about to shut down.
        return;
    }
    try {
        await exec(`sispmctl -o ${portNumber}`);
    } catch(error) {
        console.log(`Error during activating Status flag ${portNumber}:`, error);
    }
}

async function switchPortOff(portNumber) {
    try {
        await exec(`sispmctl -f ${portNumber}`);
    } catch(error) {
        console.log(`Error during deactivating Status flag ${portNumber}:`, error);
    }
}

async function verifyReader() {

    //it could make sense to wait a few milliseconds here,
    // so we don't shut off the signal port 4 and 1 ms later set it on since a reader has been detected. 

    console.log('booting up, switching off ports');
    switchPortOff(3);
    switchPortOff(4);

    await delay(10000);
    //if 10 seconds after startup, the reader wasa still unable to connect, 
    //we asume an internal error of the pcscd service and restart it.
    if (!lastDetectedReader) {
        try {
            console.error("no reader found - restarting pcscd.");
            await exec(`systemctl restart pcscd`);
        } catch (error) {
            console.error("tried to restart pcscd service");
        }
    }
}

async function shutdownComputer() {
    try {
        isShuttingDown = true;
        console.log('shutting down machine');
        await exec(`shutdown --poweroff`);
    } catch(error) {
        console.log(`Error during shutdown`, error);
    }
}

async function updateBlockchainAvailableStatus() {

    try {
        const latestBlockNumber = await sign.getLatestBlockNumber();
        console.log(`latestBlockNumber: ${latestBlockNumber}`);
        switchPortOn(2);
    } catch (error) {
        console.log('error trying to get latestBlock, could not interact with blockchain.');
        switchPortOff(2);
    }
}

verifyReader();
updateBlockchainAvailableStatus();


pcsc.on('reader', function(reader) {

    lastDetectedReader = reader;

    console.log('New reader detected', reader.name);

    switchPortOn(4);

    //console.log('card present: ' + this.SCARD_STATE_PRESENT);
    reader.on('error', function(err) {
        console.log('Error(', this.name, '):', err.message);
    });

    reader.on('status', async function(status) {
        console.log('Status(', this.name, '):', status);
        /* check what has changed */
        var changes = this.state ^ status.state;
        if (changes) {
            console.log('changes detected');
            console.log(changes);
            switchPortOff(3);

            if (lastStateWasCard && (changes & reader.SCARD_STATE_EMPTY) && (status.state & reader.SCARD_STATE_EMPTY)) {

                lastStateWasCard = false;
                console.log("card removed");/* card removed */
                reader.disconnect(reader.SCARD_LEAVE_CARD, function(err) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log('Disconnected');
                    }
                    sign.takeCard();
                });
            } else if (!lastStateWasCard && (changes & reader.SCARD_STATE_PRESENT) && (status.state & reader.SCARD_STATE_PRESENT)) {

                //if (shutdownCards)
                var card = new web3s2g.Security2GoCard(reader);
                var address = await card.getAddress(1);

                if (terminatorCards[address]) {
                  console.log(`shutdown card found ${address}:`);
                  await switchPortOff('all');
                  await shutdownComputer();
                  return;
                } else {
                    console.log('no shutdown procedure');
                }

            
                lastStateWasCard = true;
                console.log('putting card');
                switchPortOn(3);
                sign.putCard(card);
            }
        }
    });

    reader.on('end', function() {
        console.log('Reader',  this.name, 'removed');
        switchPortOff(3);
        switchPortOff(4);
    });
});

pcsc.on('error', function(err) {
    console.log('PCSC error', err.message);
});

setInterval(updateBlockchainAvailableStatus, 5000);
//test();
