echo $1

if [ $1 = "migrate" ]
then
 sh run_migrations.sh
else
 cd ca
 go run main.go
fi