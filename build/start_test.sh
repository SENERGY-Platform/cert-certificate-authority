sh run_migrations.sh 
go test -v -race -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o /coverage/coverage.html
mv coverage.out /coverage/coverage.out