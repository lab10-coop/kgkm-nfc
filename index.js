
var pcsc = require('@pokusew/pcsclite');
const sign = require('./sign');

const util = require('util');
const exec = util.promisify(require('child_process').exec);

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

var pcsc = pcsc();

//const SCARD_STATE_EMPTY = ;
var lastStateWasCard = false;

var lastDetectedReader = false;

const delay = ms => new Promise(res => setTimeout(res, ms));

async function switchPortOn(portNumber) {
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

    reader.on('status', function(status) {
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
            
                lastStateWasCard = true;
                console.log('putting card');
                switchPortOn(3);
                sign.putCard(reader);
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

//test();
