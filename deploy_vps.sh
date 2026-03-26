#!/bin/bash

# RewardLoop - Deployment Script for VPS
# Usage: ./deploy_vps.sh

echo "=========================================="
echo " Starting Deployment for RewardLoop..."
echo "=========================================="

# 1. Install Node.js dependencies
if [ -d "node_modules" ]; then
    echo "Check: node_modules exists. Skipping full install..."
else
    echo "Installing dependencies..."
    npm install
fi

# 2. Rebuild SQLite3 for Linux (Critical step when moving from Windows)
echo "Rebuilding SQLite3..."
npm rebuild sqlite3

# 3. Setup PM2 (Process Manager)
# Check if PM2 is installed
if ! command -v pm2 &> /dev/null; then
    echo "PM2 not found. Installing global PM2..."
    npm install pm2 -g
fi

# 4. Start the Application
# Check if app is already running
if pm2 list | grep -q "rewardloop"; then
    echo "App 'rewardloop' is already running. Restarting..."
    pm2 restart rewardloop
else
    echo "Starting 'rewardloop' on port 3008..."
    pm2 start server.js --name "rewardloop"
fi

# 5. Save PM2 list to resurrect on reboot
pm2 save

# 6. Firewall Configuration (UFW) - Optional but recommended
if command -v ufw &> /dev/null; then
    echo "Configuring Firewall (UFW) to allow port 3008..."
    ufw allow 3008
    echo "Port 3008 opened."
fi

echo "=========================================="
echo " Deployment Complete!"
echo " Access your app at: http://187.77.177.202:3008"
echo "=========================================="
