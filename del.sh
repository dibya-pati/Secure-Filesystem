mkdir -p /mnt/sgfs/folder

cp Data/small.txt /mnt/sgfs/;./del -mce -f=/mnt/sgfs/small.txt;
cp Data/large.txt /mnt/sgfs/folder/;./del -mce -f=/mnt/sgfs/folder/large.txt;

co=1
maxFiles=50

while [ $co -lt $maxFiles ]
do
	fName="/mnt/sgfs/rnd$co"
	cp Data/xl "$fName"
	co=`expr $co + 1`
done
echo "Copy Done"

co=1
while [ $co -lt $maxFiles ]
do
	fName="/mnt/sgfs/rnd$co"
	./del -mce "-f=$fName"
	#rm -f "$fName"
	co=`expr $co + 1`
#	sleep 1
done
