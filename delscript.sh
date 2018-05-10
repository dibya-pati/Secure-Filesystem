while true
do
	touch /mnt/sgfs/newfile
	dd if=<(openssl enc -aes-256-ctr -pass pass:"$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64)" -nosalt < /dev/zero) of=/mnt/sgfs/filename bs=1M count=10 iflag=fullblock
	echo "file created"
	rm -f /mnt/sgfs/filename
	echo "file deleted"
	sleep 61
done






