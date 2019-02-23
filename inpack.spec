[project]
name = postgresql-keeper
version = 0.9.5
vendor = sysinner.com
homepage = https://www.sysinner.com
groups = dev/db
description = configuration management tool for PostgreSQL

%build
PREFIX="/opt/postgresql/keeper"

mkdir -p {{.buildroot}}/{bin,log}

go build -ldflags "-w -s" -o {{.buildroot}}/bin/postgresql-keeper main.go

%files
misc/
README.md
LICENSE


