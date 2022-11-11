DB_URL="$DB_DRIVER://$DB_USERNAME:$DB_PASSWORD@$DB_ADDR/$DB_DATABASE?sslmode=disable up"
echo $DB_URL
alias run="goose -dir ca/migrations $DB_DRIVER $DB_URL"
for i in 1 2 3 4 5; do run && break || sleep 15; done

