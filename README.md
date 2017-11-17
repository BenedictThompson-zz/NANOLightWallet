# RetroXRBWallet

**Warning this is super beta test, your wallet seed is unencrypted in the config.ini file (though not passed to the server) so please just use this for testing**

## Installation

You will need:
* Python3
* Pip3 (to install the required libraries

To install:
* Go into the python-pure25519-blake directory and install this `python3 setup.py install`
* Using pip3 install
```
urwid
websocket
websocket-client
pyblake2 ( Microsoft Visual C++ 14.0 is required on Windows)
bitstring
```
* Run the wallet `python3 gui.py`, if it errors install the necessary missing libs


## Tips
* You can copy from the wallet by holding down your OSes modifier key, OS X its *fn*, and selecting the address
* Currently you only have a single address
* Your setting are in config.ini
* The lite wallet does all the signing itself so doesnt pass you wallet seed or private keys to the server/network