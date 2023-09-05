#! /bin/bash

name=`echo $1 | awk '{
     

    n=split($0, arr, "/")
    print arr[n]
}'`
echo $name
mv $1 $1.bak
mkdir $1
mv $1.bak $1/$name
unzip $1/$name -d $1
cd $1
apktool d $name
rm $name

