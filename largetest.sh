co=1
maxFiles=20

while [ $co -lt $maxFiles ]
do
fName="/mnt/sgfs/rndxl$co"
cp Data/xl "$fName"
co=`expr $co + 1`
done
echo "Copy Done"


co=1
while [ $co -lt $maxFiles ]
do
fName="/mnt/sgfs/rndxl$co"
./del -mce "-f=$fName"
co=`expr $co + 1`
done

echo "Success: Large test"
