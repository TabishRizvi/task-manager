#!/bin/bash

echo "Giving permissions"
chmod 775 -R .
echo "Permissions granted"


echo "Restarting servers"
sudo pm2 restart 9 || exit
echo "Servers restarted"



echo "Deployed"