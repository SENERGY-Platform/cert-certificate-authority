echo $1
if [ $1 = "migrate" ]
then
 sh run_migrations.sh
else
    if [ $1 = "migrate_and_start" ]
    then
      sh run_migrations.sh
      ./app
    else
      ./app
    fi
fi