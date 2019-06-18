
var pcsc = require('pcsclite');
const sign = require('./sign');

// testcode: runable with "node ."

// async function test()
// {
//     var wrapper = new security2goWrapper();
//     let publickey = await wrapper.getPublicKey(1);
//     console.log('publickey: ' + publickey);
//     let signature = await wrapper.generateSignature(1, "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
//     console.log('signature: ' + signature);
// }


var pcsc = pcsc();

const NO_CARD = 18;
const YES_CARD = 65584;

//const SCARD_STATE_EMPTY = ;
var lastStateWasCard = false;

pcsc.on('reader', function(reader) {

    console.log('New reader detected', reader.name);
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
                sign.putCard(reader);
            }
        }
    });

    reader.on('end', function() {
        console.log('Reader',  this.name, 'removed');
    });
});

pcsc.on('error', function(err) {
    console.log('PCSC error', err.message);
});

//test();
