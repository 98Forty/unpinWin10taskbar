XDECoin v3 | Source Code
=======

This is A Community Takeover of XDoubleEagle.

Official Thread: https://bitcointalk.org/index.php?topic=841830

Website: http://xdecoin.org

Official Forum: http://doubleeagletalk.org

----------------------------------------------------------------------
BlockchainFiles


XDECoin Blockchain Files to Fix the Stuck Issues.

---------------------------------------------
HOW TO USE THE BLOCKCHAIN FILES?
You need to have these files before Compiling and Launching the "daemon server"

YOU HAVE 2 CHOICES:

------ CHOICE 1 -----------
-1st Create the XDE Wallet Directory: .XDECoin
mkdir ~/.XDECoin

-2nd Git Clone XDE Blockchain Files: https://github.com/XDEDev/BlockchainFiles

-3rd Copy all Contents in the BlockchainFiles directory to .XDECoin
cp -a /BlockchainFiles/. /.XDECoin/

-4th Git Clone XDECoin Source: https://github.com/XDEDev/XDECoin
Compile your daemon "xdecoind"
Launch "xdecoind" it ask for a Conf file.
Create the xdecoin.conf file and Relaunch XDE Daemon "xdecoind"

------ CHOICE 2 --------------
QUICK AND EASY:

-1st Git Clone XDE Blockchain Files: https://github.com/XDEDev/BlockchainFiles
Rename "BlockchainFiles" directory to ".XDECoin"
ex: mv BlockchainFiles .XDECoin

-2nd Git Clone XDECoin Source: https://github.com/XDEDev/XDECoin
Compile your daemon "xdecoind"
Launch "xdecoind" it ask for a Conf file.
Create the xdecoin.conf file and Relaunch XDE Daemon "xdecoind"

----------------------------------------------------------------------

Tor included - Compiling:

First you need to Update your Linux OS (Ubuntu)

1) sudo apt-get update

2) sudo apt-get upgrade

3) sudo apt-get install build-essential libssl-dev libboost-all-dev git libdb5.1++-dev libminiupnpc-dev screen

4) sudo apt-get install libevent-dev

-----------------------------------------------------------------------
Compilation Errors at End: libleveldb.a and libmemenv.a - Not Found! ! !

When Compiling xdecoind on Linux, if compilation get terminated at the end because of missing files:
libleveldb.a and libmemenv.a - Please use these commands to copy the Files from "src/leveldblinux directory.

1) cd XDECoin/src/leveldblinux

2) sudo cp libleveldb.a /XDECoin/src/leveldb

3) sudo cp libmemenv.a /XDECoin/src/leveldb

------------------------------------------------------------------------
