echo $@
if [ $@ = "migrate" ]
then
 goose -dir migrations $DB_DRIVER $DB_URL up
fi

cd ca
go run main.go

