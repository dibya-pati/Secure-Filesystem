co=1
maxFiles=20

while [ $co -lt $maxFiles ]
do
fName="/mnt/sgfs/rndsmall$co"
cp Data/small.txt "$fName"
co=`expr $co + 1`
done
echo "Copy Done"


co=1
while [ $co -lt $maxFiles ]
do
fName="/mnt/sgfs/rndsmall$co"
./del -m "-f=$fName"
co=`expr $co + 1`
done
echo "Success: small test"
