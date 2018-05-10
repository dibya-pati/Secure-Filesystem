for entry in "$@"/*
do
  echo ./restore -f="$entry"
done
