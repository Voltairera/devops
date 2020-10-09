#!/bin/sh

Time=$(date)
Env=$(env)

# Change these two lines:
sender="voltpoolalerts@gmail.com"
recepient="sshalert@voltairera.com"

if [ "$PAM_TYPE" != "close_session" ]; then
 host="`hostname`"
 subject="SSH Login: $PAM_USER from $PAM_RHOST on $host"

 # Message to send, e.g. the current environment variables.
# message="`env`"
  message="ALERT SSH LOGIN:
  USER: $PAM_USER 
  FROM: $PAM_RHOST
  ON: $host
  TIME: "$Time"
  INFO:
 
  "$Env""

 echo "$message" | mailx -r "$sender" -s "$subject" "$recepient"
 fi