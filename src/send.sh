#!/bin/bash

sender=$(sudo grep mailsender /usr/share/urnis/src/urnis.conf | cut -c 13- | sed 's/"//g')
passw=$(sudo grep password /usr/share/urnis/src/urnis.conf | cut -c 10- | sed 's/"//g')
reciver=$(sudo grep mailreciver /usr/share/urnis/src/urnis.conf | cut -c 13- | sed 's/"//g')

sudo python3 /usr/share/urnis/src/mailsender.py ${sender} ${passw} ${reciver}

curl -d "audit send by mail" ntfy.sh/urnissec