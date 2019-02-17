// Copyright 2018 Eryx <evorui at gmail dot com>, All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hflag4g/hflag"
	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/sysinner/incore/inconf"
	"github.com/sysinner/incore/inutils/filerender"
)

var (
	pg_rel     = "96"
	pg_rels    = types.ArrayString([]string{"95", "96", "10", "11"})
	pg_prefix  = "/home/action/apps/postgresql"
	pg_mem_min = int32(16) // in MiB
	mu         sync.Mutex
	cfg_mu     sync.Mutex
	cfg_last   EnvConfig
	cfg_next   EnvConfig
	pgPodCfr   *inconf.PodConfigurator
)

func pg_path(path string) string {
	return filepath.Clean("/home/action/apps/postgresql/" + path)
}

func pgrel_path(path string) string {
	return filepath.Clean("/home/action/apps/postgresql" + pg_rel + "/" + path)
}

type EnvConfig struct {
	Inited   bool              `json:"inited"`
	RootAuth string            `json:"root_auth"`
	Resource EnvConfigResource `json:"resource"`
	Database EnvConfigDatabase `json:"database"`
	Users    []EnvConfigUser   `json:"users"`
	Updated  time.Time         `json:"updated"`
}

type EnvConfigResource struct {
	Ram int32 `json:"ram"`
	Cpu int32 `json:"cpu"`
}

type EnvConfigDatabase struct {
	Name  string       `json:"name"`
	Items types.Labels `json:"items"`
}

type EnvConfigUser struct {
	Name string `json:"name"`
	Auth string `json:"auth"`
}

func (cfg *EnvConfig) UserSync(item EnvConfigUser) {

	cfg_mu.Lock()
	defer cfg_mu.Unlock()

	for i, v := range cfg.Users {

		if v.Name == item.Name {
			cfg.Users[i] = item
			return
		}
	}

	cfg.Users = append(cfg.Users, item)
}

func (cfg *EnvConfig) UserGet(name string) *EnvConfigUser {

	cfg_mu.Lock()
	defer cfg_mu.Unlock()

	for _, v := range cfg.Users {

		if v.Name == name {
			return &v
		}
	}

	return nil
}

func main() {

	if v, ok := hflag.ValueOK("pg_rel"); ok && pg_rels.Has(v.String()) {
		pg_rel = v.String()
	}

	for {
		time.Sleep(3e9)
		do()
	}
}

func do() {

	fpbin, err := os.Open(pgrel_path("bin/postgres"))
	if err != nil {
		hlog.Print("error", err.Error())
		return
	}
	fpbin.Close()

	var (
		tstart = time.Now()
		podCfr *inconf.PodConfigurator
		appCfg *inconf.AppConfigGroup
	)

	cfg_next = EnvConfig{}

	//
	{
		if pgPodCfr != nil {
			podCfr = pgPodCfr

			if !podCfr.Update() {
				return
			}

		} else {

			if podCfr, err = inconf.NewPodConfigurator(); err != nil {
				hlog.Print("error", err.Error())
				return
			}
		}

		appCfr := podCfr.AppConfigurator("sysinner-pgsql-*")
		if appCfr == nil {
			hlog.Print("error", "No AppSpec (sysinner-pgsql) Found")
			return
		}
		if appCfg = appCfr.AppConfigQuery("cfg/sysinner-pgsql"); appCfg == nil {
			hlog.Print("error", "No AppSpec (sysinner-pgsql) Found")
			return
		}

		if podCfr.PodSpec().Box.Resources.MemLimit > 0 {
			cfg_next.Resource.Ram = podCfr.PodSpec().Box.Resources.MemLimit
		}
		if podCfr.PodSpec().Box.Resources.CpuLimit > 0 {
			cfg_next.Resource.Cpu = podCfr.PodSpec().Box.Resources.CpuLimit
		}
	}

	if v, ok := appCfg.ValueOK("db_name"); ok {
		cfg_next.Database = EnvConfigDatabase{
			Name: v.String(),
		}
	} else {
		hlog.Print("error", "No db_name Found")
		return
	}

	if v, ok := appCfg.ValueOK("db_user"); ok {

		vp, ok := appCfg.ValueOK("db_auth")
		if !ok {
			hlog.Print("error", "No db_auth Found")
			return
		}

		cfg_next.UserSync(EnvConfigUser{
			Name: v.String(),
			Auth: vp.String(),
		})

	} else {
		hlog.Print("error", "No db_user Found")
		return
	}

	if v, ok := appCfg.ValueOK("memory_usage_limit"); ok {

		ram_pc := v.Int32()

		if ram_pc < 10 || ram_pc > 100 {
			hlog.Print("error", "Invalid memory_usage_limit Setup")
			return
		}

		ram_pc = (cfg_next.Resource.Ram * ram_pc) / 100
		if offset := ram_pc % pg_mem_min; offset > 0 {
			ram_pc -= offset
		}
		if ram_pc < pg_mem_min {
			ram_pc = pg_mem_min
		}
		if ram_pc < cfg_next.Resource.Ram {
			cfg_next.Resource.Ram = ram_pc
		}

	} else {
		hlog.Print("error", "No memory_usage_limit Found")
		return
	}

	//
	if cfg_next.Resource.Ram < pg_mem_min {
		hlog.Print("error", "Not enough Memory to fit this PostgreSQL Instance")
		return
	}

	//
	if cfg_last.Database.Name == "" {
		json.DecodeFile(pgrel_path("init_option.json"), &cfg_last)
	}

	// s1
	if err := init_datadir(); err != nil {
		hlog.Print("error", err.Error())
		return
	}

	//
	if err := init_conf(); err != nil {
		hlog.Print("error", err.Error())
		return
	}

	if cfg_last.Resource.Ram != cfg_next.Resource.Ram {
		if err := restart(); err != nil {
			hlog.Print("error", err.Error())
			return
		}
		cfg_last.Resource.Ram = cfg_next.Resource.Ram
		cfg_last.Resource.Cpu = cfg_next.Resource.Cpu

	} else {

		if err := start(); err != nil {
			hlog.Print("error", err.Error())
			return
		}
	}

	// s3
	if err := init_db(); err != nil {
		hlog.Printf("error", "init_db %s", err.Error())
		return
	}

	if err := init_user(); err != nil {
		hlog.Printf("error", "init_user %s", err.Error())
		return
	}

	hlog.Printf("info", "setup in %v", time.Since(tstart))

	pgPodCfr = podCfr
}

func init_conf() error {

	if cfg_last.Inited && cfg_last.Resource.Ram == cfg_next.Resource.Ram {
		return nil
	}

	//
	ram := int(cfg_next.Resource.Ram)
	sets := map[string]interface{}{
		"project_prefix": pg_prefix,
		"env_ram_size":   fmt.Sprintf("%dM", ram),
		// "server_key_buffer_size":         fmt.Sprintf("%dM", ram/4),
		// "server_query_cache_size":        fmt.Sprintf("%dM", ram/8),
		// "server_innodb_buffer_pool_size": fmt.Sprintf("%dM", ram/4),
	}

	if !cfg_last.Inited || cfg_last.Resource.Ram != cfg_next.Resource.Ram {

		if err := filerender.Render(pg_path("misc/"+pg_rel+"/postgresql.conf.sample"),
			pgrel_path("data/postgresql.conf"),
			0644, sets); err != nil {
			return err
		}

		if err := filerender.Render(pg_path("misc/"+pg_rel+"/pg_hba.conf.sample"),
			pgrel_path("data/pg_hba.conf"),
			0644, sets); err != nil {
			return err
		}

		cfg_last.Resource.Ram = cfg_next.Resource.Ram
		cfg_last.Resource.Cpu = cfg_next.Resource.Cpu
	}

	return nil
}

func init_datadir() error {

	mu.Lock()
	defer mu.Unlock()

	if cfg_last.Inited {
		return nil
	}

	if cfg_last.RootAuth != "" {
		return errors.New("Root Password Already Setup")
	}

	// writeable test!
	cfg_last.Updated = time.Now()
	if err := json.EncodeToFile(cfg_last, pgrel_path("init_option.json"), "  "); err != nil {
		return err
	}

	_, err := os.Open(pgrel_path("data/postgresql.conf"))
	if err != nil && os.IsNotExist(err) {
		_, err = exec.Command(pgrel_path("bin/initdb"), "-D", pgrel_path("data")).Output()
		if err != nil {
			hlog.Printf("error", "initdb %s", err.Error())
		} else {
			hlog.Printf("info", "initdb ok")
		}
	}

	if err == nil {
		cfg_last.Inited = true
		err = json.EncodeToFile(cfg_last, pgrel_path("init_option.json"), "  ")
	}

	return err
}

func clean_runlock() {
	os.Remove(pgrel_path("postmaster.pid"))
}

func start() error {

	mu.Lock()
	defer mu.Unlock()

	hlog.Printf("info", "start()")

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	if pidof() > 0 {
		return nil
	}

	clean_runlock()
	os.Chmod(pgrel_path("data"), 0700)
	_, err := exec.Command(pgrel_path("bin/pg_ctl"),
		"-D", pgrel_path("data"),
		"-l", pgrel_path("server_logfile.log"), "start").Output()

	time.Sleep(1e9)

	if err != nil {
		hlog.Printf("error", "start postgres %s", err.Error())
	} else {
		hlog.Printf("info", "start postgres ok")
	}

	return err
}

func restart() error {

	mu.Lock()
	defer mu.Unlock()

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	var err error

	if pid := pidof(); pid > 0 {
		hlog.Printf("info", "kill HUP %d", pid)
		_, err = exec.Command(pgrel_path("bin/pg_ctl"),
			"-D", pgrel_path("data"),
			"-l", pgrel_path("server_logfile.log"), "stop").Output()
		if err != nil {
			hlog.Printf("error", "kill HUP %s", err.Error())
		} else {
			hlog.Printf("info", "kill HUP ok")
		}

	} else {
		clean_runlock()
		os.Chmod(pgrel_path("data"), 0700)
		_, err = exec.Command(pgrel_path("bin/pg_ctl"),
			"-D", pgrel_path("data"),
			"-l", pgrel_path("server_logfile.log"), "start").Output()
		time.Sleep(1e9)
		if err != nil {
			hlog.Printf("error", "start postgres %s", err.Error())
		} else {
			hlog.Printf("info", "start postgres ok")
		}
	}

	return err
}

func pidof() int {

	//
	for i := 0; i < 3; i++ {

		pidout, err := exec.Command("pgrep", "-f", pgrel_path("bin/postgres")).Output()
		pid, _ := strconv.Atoi(strings.TrimSpace(string(pidout)))

		if err != nil || pid == 0 {
			time.Sleep(3e9)
			continue
		}

		return pid
	}

	return 0
}

func init_db() error {

	mu.Lock()
	defer mu.Unlock()

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	var err error

	if cfg_next.Database.Name != "" &&
		cfg_last.Database.Name == "" {

		exec.Command(pgrel_path("bin/createuser"), "-D", "dbuser").Output()

		_, err = exec.Command(pgrel_path("bin/createdb"),
			"--owner=dbuser", cfg_next.Database.Name).Output()
		if err != nil {
			hlog.Printf("error", "initdb %s", err.Error())
		} else {
			hlog.Printf("info", "initdb ok")
		}

		hlog.Printf("info", "create database %s ok", cfg_next.Database.Name)

		cfg_last.Database = cfg_next.Database
		err = json.EncodeToFile(cfg_last, pgrel_path("init_option.json"), "  ")
	}

	return err
}

func init_user() error {

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	if cfg_last.Database.Name == "" {
		return errors.New("No Database Found")
	}

	var err error

	for _, v := range cfg_next.Users {

		if prev := cfg_last.UserGet(v.Name); prev == nil || prev.Auth != v.Auth {

			cmd := exec.Command("/bin/bash")
			stdin, err := cmd.StdinPipe()
			if err != nil {
				return err
			}

			cmd_str := fmt.Sprintf("%s -U %s -d %s -c \"ALTER USER %s PASSWORD '%s'\"",
				pgrel_path("bin/psql"), v.Name, cfg_last.Database.Name, v.Name, v.Auth)

			go func() {
				defer stdin.Close()
				io.WriteString(stdin, cmd_str)
			}()

			if _, err = cmd.CombinedOutput(); err != nil {
				hlog.Printf("error", "set user %s %s", err.Error(), cmd_str)
				return err
			}

			hlog.Printf("info", "set user %s", v.Name)

			cfg_last.UserSync(v)
			err = json.EncodeToFile(cfg_last, pgrel_path("init_option.json"), "  ")
		}
	}

	return err
}
