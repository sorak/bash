#! /bin/bash

# pull/push script
branch=`git status|grep 'On branch'|sed 's/^On branch //'`
git pull origin $branch
git push origin $branch

