
Copy-Item -Path "admin_plans.html" -Destination "Admin_Panel_Backup" -Force
Copy-Item -Path "admin_portfolios.html" -Destination "Admin_Panel_Backup" -Force
Copy-Item -Path "check_chat_table.js" -Destination "Admin_Panel_Backup" -Force
Write-Host "Missing files copied."
