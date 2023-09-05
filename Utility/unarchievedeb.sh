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
ls 
ar -x $name
mkdir data
if [ -f data.tar.xz ]; then
	mv data.tar.xz data/data.tar.xz
	cd data
	xz -d data.tar.xz
	tar xf data.tar
	rm data.tar
	cd ..
fi
if [ -f data.tar.gz ]; then
	mv data.tar.gz data/data.tar.gz
	cd data
	tar -zxf data.tar.gz
	rm data.tar.gz
	cd ..
fi
mkdir control
if [ -f control.tar.xz ]; then
	mv control.tar.xz control/control.tar.xz
	cd control
	xz -d control.tar.xz
	tar xf control.tar
	rm control.tar
	cd ..
fi
if [ -f control.tar.gz ]; then
	mv control.tar.gz control/control.tar.gz
	cd control
	tar -zxf control.tar.gz
	rm control.tar.gz
	cd ..
fi




