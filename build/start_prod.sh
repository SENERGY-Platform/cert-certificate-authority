echo $1
if [ $1 = "migrate" ]
then
 sh run_migrations.sh
else
./app
fi