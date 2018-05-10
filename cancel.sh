#attempt canceling a job from the job id from /proc/fs/sgfs/
while true
do
	./canceljob -f=/mnt/sgfs/.metadata -j=35
	sleep 1
done
