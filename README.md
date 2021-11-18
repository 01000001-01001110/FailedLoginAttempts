# FailedLoginAttempts
PowerShell script to pull failed login attempts and email the list.

Script was written to run in a scheduled task. 

Queries AD for Failed login attempts, saves to a CSV, emails CSV to recipients, and deletes said CSV. 
