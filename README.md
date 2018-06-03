## btsnoop_parser

Experimental parser for Bluetooth snoop log (btsnoop_hci.log) from Android.
The parser use Wireshark/Tshark under the hood, so please make sure it is
install in your system.

## Install:
If you don't have wireshartk/tshark install, please do so:
```
    $ sudo apt-get install wireshark
```
Suggest to use virtual environment to isolate changes to Python library.
1. Make sure you have pip installed:
```
    $ sudo apt-get update
    $ sudo apt-get -y install python-pip
```

2. Install virtualenv:
```
    $ pip install virtualenv
```

3. Navigate to a folder where you want to keep your virtual environment and
   create the virtualenv:
```
    $ virtualenv venv
    $ source venv/bin/active
```

Run setup script to install uncessary Python packages:
```
    $ python setup.py install
```

## Usage:
```
    $ python find_connection_time.py [-v] <path to btsnoop_hci.log>
```

An example btsnoop log file is included.


Have fun!
