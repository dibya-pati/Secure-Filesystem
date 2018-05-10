co=1
maxFiles=20

while [ $co -lt $maxFiles ]
do
fName="/mnt/sgfs/rndmed$co"
cp Data/large.txt "$fName"
co=`expr $co + 1`
done
echo "Copy Done"


co=1
while [ $co -lt $maxFiles ]
do
fName="/mnt/sgfs/rndmed$co"
./del -me "-f=$fName"
co=`expr $co + 1`
done

echo "Success: Medium test"
