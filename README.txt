When scan dmg files, hfs driver must be loaded before running.
lsmod | grep hfs
if hfsplus is not found, then run:
sudo modprobe hfsplus

It needs 7z and in path environment
