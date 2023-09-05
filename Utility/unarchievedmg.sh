#! /bin/bash


name=`echo $1 | awk '{
     

    n=split($0, arr, "/")
    print arr[n]
}'`
echo $name

pwd
echo $1
dmg2img -i $1 -o tmp/tmp.img
cd tmp
rm $name
mkdir mnt
sudo mount tmp.img mnt 2> log
A=$(rev log | cut -d ':' -f1| sed -n 1,1p)
if [ "$A" == '.ecived no tfel ecaps oN ' ];then
    sudo mount tmp.img mnt
fi
#rm log
cp -r ./mnt ./$name
sudo umount mnt
#rm -rf mnt
#rm tmp.img

