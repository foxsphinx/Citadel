#! /bin/bash

name=`echo $1 | awk '{
     

    n=split($0, arr, "/")
    print arr[n]
}'`
echo $name $1
mv $1 $1.bak
mkdir $1
mv $1.bak $1/$name
cd $1
rpm2cpio $name| cpio -div  
rm $name
cd ..
