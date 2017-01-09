Afero Beetle Library
====================

*Version 1.0.221*

**Beetle** is a daemon that provides the interface between the Linux “BlueZ” Bluetooth® package and the Afero Hub Software.

The Afero Hub Software provides connectivity between Afero ASR-1s and the Afero Cloud. Beetle provides a standard interface for the Afero Hub Software to communicate with the Linux Bluetooth stack.

Beetle is released under The MIT License. See the accompanying LICENSE file for terms and conditions.

### Supported Devices
---------------------

This software has been tested on a Raspberry Pi® 3 and a Raspberry Pi Zero (with USB attached Wifi and BT adapters) and should work on any model and revision of Pi hardware. Please see the [Afero Developer Documentation][link1] for important information on supported Operating System limitations. Future releases of Beetle will provide support for other similar hardware architectures.

### Build and Installation
--------------------------

**beetle** is a very straightforward daemon with few build requirements.

To build **beetle** on a Raspberry Pi, you will need to install the libbluetooth-dev package to install the required C headers. Run "sudo apt-get install libbluetooth-dev" and install that package and it's dependencies.

To compile, simply run "make". To install **beetle** to your system, run "sudo make install".

For questions or assistance with **beetle**, please visit the [Afero Developer Forums][link2].

Copyright Afero, Inc. 2017

[link1]: https://developer.afero.io/docs/en/?target=StandaloneHub.htm†
[link2]: https://forum.afero.io/
