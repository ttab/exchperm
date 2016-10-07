Description
-----------
Script loops through all sec groups within a specific OU and enables full / send access for all members to mailbox which is specified in the group descriptions field with the SMTP adress.
Script removes access to the mailbox if users is removed from sec group.

Requirement
-----------
Description field on the AD-object ( the shared mailbox user ) is going to be used to save the " uSNChanged " value from sec group. So the script can match the current value on group. This way the script dont need to run the whole script, only if the sec groups have been modified.
