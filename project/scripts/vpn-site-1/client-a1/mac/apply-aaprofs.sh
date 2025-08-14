#!/bin/bash

PROFSDIR=aaprofs
PROFILES=$(ls $PROFSDIR)

echo "Entering directory $PROFSDIR..."
echo "=================="
echo "------------------"

cd $PROFSDIR

for profile in $PROFILES; do
        echo "Applying AppArmor profile: $profile"
        cp $profile /etc/apparmor.d/$profile
        apparmor_parser /etc/apparmor.d/$profile
        apparmor_parser -r /etc/apparmor.d/$profile
        aa-enforce /etc/apparmor.d/$profile
        echo "------------------"
done

echo "=================="
echo "Exiting directory $PROFSDIR..."

cd ..
