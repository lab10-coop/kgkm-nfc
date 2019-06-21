# kgkm-nfc

"Ka Göd ka Musi" was die winning project of the 24 Hour Infineon Blockchain Hackathon.

https://www.youtube.com/watch?v=TqVXTohUEpI

https://www.youtube.com/watch?v=vT8lANjT620

See also the related project: 
https://github.com/lab10-coop/kgkm-power-switcher

## Requirements

- Raspberry Pi 3 (other Linux compatible hardware should work as well)
- Raspbian (other Linux should work as well)
- NFC Card Reader (tested with Identiv uTrust 3700 F CL Reader)
- Infineon Security2Go NFC Card (https://github.com/Infineon/Blockchain/)

## Setup

Install the dependend [Infineon BlockchainSecurity2Go-Python-Library](https://github.com/Infineon/BlockchainSecurity2Go-Python-Library) from source.
- Install NPM & Node (tested with v10.15.3)

```
apt-get install libpcsclite1 libpcsclite-dev
git clone https://github.com/lab10-coop/kgkm-nfc.git
cd kgkm-nfc
npm install
```

## Running
```
npm start
```

The project is a node-js server that starts and stops so Streems of a streemable token (see also [streem-poc](https://github.com/lab10-coop/streem-poc)).

The Node Server communicates with an USB Connected NFC Card Reader to create an [ECC-Signature](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) that is further used to create a Ethereum signature for starting and stopping the streem.


See also: requirements for pcsc. https://github.com/santigimeno/node-pcsclite
