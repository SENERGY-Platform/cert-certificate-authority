echo $@
if [ $@ = "migrate" ]
then
 goose -dir migrations $DB_DRIVER $DB_URL up
else
 cd ca
 go run main.go
fi

