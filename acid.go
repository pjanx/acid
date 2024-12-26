package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	ttemplate "text/template"
	"time"
	"unicode"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var (
	projectName    = "acid"
	projectVersion = "?"

	gConfigPath string
	gConfig     atomic.Pointer[Config]
	gDB         *sql.DB

	gNotifierSignal = make(chan struct{}, 1)
	gExecutorSignal = make(chan struct{}, 1)

	// The mutex is at least supposed to lock over the tasks as well.
	gRunningMutex sync.Mutex
	gRunning      = make(map[int64]*RunningTask)
)

func getConfig() *Config { return gConfig.Load() }

// --- Config ------------------------------------------------------------------

type Config struct {
	DB     string `yaml:"db"`     // database file path
	Listen string `yaml:"listen"` // HTTP listener address
	Root   string `yaml:"root"`   // HTTP root URI
	Gitea  string `yaml:"gitea"`  // Gitea base URL
	Secret string `yaml:"secret"` // Gitea hook secret
	Token  string `yaml:"token"`  // Gitea API token
	Notify string `yaml:"notify"` // notifier script

	Runners  map[string]ConfigRunner  `yaml:"runners"`  // script runners
	Projects map[string]ConfigProject `yaml:"projects"` // configured projects

	notifyTemplate *ttemplate.Template
}

type ConfigRunner struct {
	Name   string `yaml:"name"`   // descriptive name
	Manual bool   `yaml:"manual"` // only run on request
	Run    string `yaml:"run"`    // runner executable
	Setup  string `yaml:"setup"`  // runner setup script (SSH)
	SSH    struct {
		User     string `yaml:"user"`     // remote username
		Address  string `yaml:"address"`  // TCP host:port
		Identity string `yaml:"identity"` // private key path
	} `yaml:"ssh"` // shell access
}

type ConfigProject struct {
	Runners map[string]ConfigProjectRunner `yaml:"runners"`
}

func (cf *ConfigProject) AutomaticRunners() (runners []string) {
	// We pass through unknown runner names,
	// so that they can cause reference errors later.
	config := getConfig()
	for runner := range cf.Runners {
		if r, _ := config.Runners[runner]; !r.Manual {
			runners = append(runners, runner)
		}
	}
	sort.Strings(runners)
	return
}

type ConfigProjectRunner struct {
	Setup   string `yaml:"setup"`   // project setup script (SSH)
	Build   string `yaml:"build"`   // project build script (SSH)
	Deploy  string `yaml:"deploy"`  // project deploy script (local)
	Timeout string `yaml:"timeout"` // timeout duration
}

// loadConfig reloads configuration.
// Beware that changes do not get applied globally at the same moment.
func loadConfig() error {
	new := &Config{}
	if f, err := os.Open(gConfigPath); err != nil {
		return err
	} else if err = yaml.NewDecoder(f).Decode(new); err != nil {
		return err
	}
	if old := getConfig(); old != nil && old.DB != new.DB {
		return fmt.Errorf("the database file cannot be changed in runtime")
	}

	var err error
	new.notifyTemplate, err =
		ttemplate.New("notify").Funcs(shellFuncs).Parse(new.Notify)
	if err != nil {
		return err
	}

	gConfig.Store(new)
	return nil
}

var shellFuncs = ttemplate.FuncMap{
	"quote": func(word string) string {
		// History expansion is annoying, don't let it cut us.
		if strings.IndexRune(word, '!') >= 0 {
			return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
		}

		const special = "$`\"\\"
		quoted := []rune{'"'}
		for _, r := range word {
			if strings.IndexRune(special, r) >= 0 {
				quoted = append(quoted, '\\')
			}
			quoted = append(quoted, r)
		}
		return string(append(quoted, '"'))
	},
}

// --- Utilities ---------------------------------------------------------------

func giteaSign(b []byte) string {
	payloadHmac := hmac.New(sha256.New, []byte(getConfig().Secret))
	payloadHmac.Write(b)
	return hex.EncodeToString(payloadHmac.Sum(nil))
}

func giteaNewRequest(ctx context.Context, method, path string, body io.Reader) (
	*http.Request, error) {
	req, err := http.NewRequestWithContext(
		ctx, method, getConfig().Gitea+path, body)
	if req != nil {
		req.Header.Set("Authorization", "token "+getConfig().Token)
		req.Header.Set("Accept", "application/json")
	}
	return req, err
}

func getTasks(ctx context.Context, query string, args ...any) ([]Task, error) {
	rows, err := gDB.QueryContext(ctx, `
		SELECT id, owner, repo, hash, runner,
			created, changed, duration,
			state, detail, notified,
			runlog, tasklog, deploylog FROM task `+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasks := []Task{}
	for rows.Next() {
		var t Task
		err := rows.Scan(&t.ID, &t.Owner, &t.Repo, &t.Hash, &t.Runner,
			&t.CreatedUnix, &t.ChangedUnix, &t.DurationSeconds,
			&t.State, &t.Detail, &t.Notified,
			&t.RunLog, &t.TaskLog, &t.DeployLog)
		if err != nil {
			return nil, err
		}
		// We could also update some fields from gRunning.
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// --- Task views --------------------------------------------------------------

var templateTasks = template.Must(template.New("tasks").Parse(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Tasks</title>
</head>
<body>
<h1>Tasks</h1>
<table border="1">
<thead>
	<tr>
		<th>ID</th>
		<th>Created</th>
		<th>Changed</th>
		<th>Repository</th>
		<th>Hash</th>
		<th>Runner</th>
		<th>State</th>
		<th>Detail</th>
		<th>Notified</th>
	</tr>
</thead>
<tbody>
{{range .}}
	<tr>
		<td><a href="task/{{.ID}}">{{.ID}}</a></td>
		<td align="right"><span title="{{.Created}}">{{.CreatedAgo}}</span></td>
		<td align="right"><span title="{{.Changed}}">{{.ChangedAgo}}</span></td>
		<td><a href="{{.RepoURL}}">{{.FullName}}</a></td>
		<td><a href="{{.CommitURL}}">{{.Hash}}</a></td>
		<td>{{.RunnerName}}</td>
		<td>{{.State}}</td>
		<td>{{.Detail}}</td>
		<td>{{.Notified}}</td>
	</tr>
{{end}}
</tbody>
</table>
</body>
</html>
`))

func handleTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := getTasks(r.Context(), `ORDER BY id DESC`)
	if err != nil {
		http.Error(w,
			"Error retrieving tasks: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	if err := templateTasks.Execute(w, tasks); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var templateTask = template.Must(template.New("tasks").Parse(`
<!DOCTYPE html>
<html>
<head>
<title>Task {{.ID}}</title>
<meta charset="utf-8">
{{if .IsRunning}}
<meta http-equiv="refresh" content="5">
{{end}}
</head>
<body>
<h1><a href="..">Tasks</a> &raquo; {{.ID}}</h1>
<dl>
{{if .Created}}
<dt>Created</dt>
	<dd><span title="{{.Created}}">{{.CreatedAgo}} ago</span></dd>
{{end}}
{{if .Changed}}
<dt>Changed</dt>
	<dd><span title="{{.Changed}}">{{.ChangedAgo}} ago</span></dd>
{{end}}
<dt>Project</dt>
	<dd><a href="{{.RepoURL}}">{{.FullName}}</a></dd>
<dt>Commit</dt>
	<dd><a href="{{.CommitURL}}">{{.Hash}}</a></dd>
<dt>Runner</dt>
	<dd>{{.RunnerName}}</dd>
<dt>State</dt>
	<dd>{{.State}}{{if .Detail}} ({{.Detail}}){{end}}</dd>
<dt>Notified</dt>
	<dd>{{.Notified}}</dd>
{{if .Duration}}
<dt>Duration</dt>
	<dd>{{.Duration}}</dd>
{{end}}
</dl>
{{if .RunLog}}
<h2>Runner log</h2>
<pre>{{printf "%s" .RunLog}}</pre>
{{end}}
{{if .TaskLog}}
<h2>Task log</h2>
<pre>{{printf "%s" .TaskLog}}</pre>
{{end}}
{{if .DeployLog}}
<h2>Deploy log</h2>
<pre>{{printf "%s" .DeployLog}}</pre>
{{end}}
</table>
</body>
</html>
`))

func handleTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w,
			"Invalid ID: "+err.Error(), http.StatusBadRequest)
		return
	}

	tasks, err := getTasks(r.Context(), `WHERE id = ?`, id)
	if err != nil {
		http.Error(w,
			"Error retrieving task: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	if len(tasks) == 0 {
		http.NotFound(w, r)
		return
	}

	task := struct {
		Task
		IsRunning bool
	}{Task: tasks[0]}
	func() {
		gRunningMutex.Lock()
		defer gRunningMutex.Unlock()

		rt, ok := gRunning[task.ID]
		task.IsRunning = ok
		if !ok {
			return
		}

		task.DurationSeconds = rt.elapsed()

		rt.RunLog.Lock()
		defer rt.RunLog.Unlock()
		rt.TaskLog.Lock()
		defer rt.TaskLog.Unlock()
		rt.DeployLog.Lock()
		defer rt.DeployLog.Unlock()

		task.RunLog = rt.RunLog.Serialize(0)
		task.TaskLog = rt.TaskLog.Serialize(0)
		task.DeployLog = rt.DeployLog.Serialize(0)
	}()

	if err := templateTask.Execute(w, &task); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// --- Push hook ---------------------------------------------------------------

type GiteaPushEvent struct {
	HeadCommit struct {
		ID string `json:"id"`
	} `json:"head_commit"`
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Owner    struct {
			Username string `json:"username"`
		} `json:"owner"`
	} `json:"repository"`
}

func createTasks(ctx context.Context,
	owner, repo, hash string, runners []string) error {
	tx, err := gDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO task(owner, repo, hash, runner, created, changed)
		VALUES (?, ?, ?, ?, unixepoch('now'), unixepoch('now'))`)
	if err != nil {
		return err
	}

	for _, runner := range runners {
		if _, err := stmt.Exec(owner, repo, hash, runner); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	notifierAwaken()
	executorAwaken()
	return nil
}

func handlePush(w http.ResponseWriter, r *http.Request) {
	// X-Gitea-Delivery doesn't seem useful, pushes explode into multiple tasks.
	if r.Header.Get("X-Gitea-Event") != "push" {
		http.Error(w,
			"Expected a Gitea push event", http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w,
			"Error reading request body", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("X-Gitea-Signature") != giteaSign(body) {
		http.Error(w,
			"Signature mismatch", http.StatusBadRequest)
		return
	}

	var event GiteaPushEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w,
			"Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("received push: %s %s\n",
		event.Repository.FullName, event.HeadCommit.ID)

	project, ok := getConfig().Projects[event.Repository.FullName]
	if !ok {
		// This is okay, don't set any commit statuses.
		fmt.Fprintf(w, "The project is not configured.")
		return
	}

	runners := project.AutomaticRunners()
	if err := createTasks(r.Context(),
		event.Repository.Owner.Username, event.Repository.Name,
		event.HeadCommit.ID, runners); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// --- RPC ---------------------------------------------------------------------

const rpcHeaderSignature = "X-ACID-Signature"

var errWrongUsage = errors.New("wrong usage")

func rpcRestartOne(ctx context.Context, id int64) error {
	gRunningMutex.Lock()
	defer gRunningMutex.Unlock()

	if _, ok := gRunning[id]; ok {
		return fmt.Errorf("%d: not restarting running tasks", id)
	}

	// The executor bumps to "running" after inserting into gRunning,
	// so we should not need to exclude that state here.
	//
	// We deliberately do not clear previous run data (duration, *log).
	result, err := gDB.ExecContext(ctx,
		`UPDATE task SET changed = unixepoch('now'),
		state = ?, detail = '', notified = 0 WHERE id = ?`,
		taskStateNew, id)
	if err != nil {
		return fmt.Errorf("%d: %w", id, err)
	} else if n, _ := result.RowsAffected(); n != 1 {
		return fmt.Errorf("%d: no such task", id)
	}

	notifierAwaken()
	executorAwaken()
	return nil
}

func rpcEnqueueOne(ctx context.Context,
	owner, repo, hash, runner string) error {
	tasks, err := getTasks(ctx, `WHERE owner = ? AND repo = ? AND hash = ?
		AND runner = ? ORDER BY id DESC LIMIT 1`, owner, repo, hash, runner)
	if err != nil {
		return err
	}

	if len(tasks) != 0 {
		return rpcRestartOne(ctx, tasks[0].ID)
	} else {
		return createTasks(ctx, owner, repo, hash, []string{runner})
	}
}

func giteaResolveRef(ctx context.Context, owner, repo, ref string) (
	string, error) {
	req, err := giteaNewRequest(ctx, http.MethodGet, fmt.Sprintf(
		"/api/v1/repos/%s/%s/git/commits/%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(ref)), nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	commit := struct {
		SHA string `json:"sha"`
	}{}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	} else if err := json.Unmarshal(body, &commit); err != nil {
		return "", err
	}
	return commit.SHA, nil
}

func rpcEnqueue(ctx context.Context,
	w io.Writer, fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 3 {
		return errWrongUsage
	}

	owner, repo, ref := fs.Arg(0), fs.Arg(1), fs.Arg(2)
	hash, err := giteaResolveRef(ctx, owner, repo, ref)
	if err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}

	project, ok := getConfig().Projects[owner+"/"+repo]
	if !ok {
		return fmt.Errorf("project configuration not found")
	}

	runners := fs.Args()[3:]
	if len(runners) == 0 {
		runners = project.AutomaticRunners()
	}

	for _, runner := range runners {
		if _, ok := project.Runners[runner]; !ok {
			return fmt.Errorf("project not configured for runner %s", runner)
		}
	}
	for _, runner := range runners {
		err := rpcEnqueueOne(ctx, owner, repo, hash, runner)
		if err != nil {
			fmt.Fprintf(w, "runner %s: %s\n", runner, err)
		}
	}
	return nil
}

func rpcRestart(ctx context.Context,
	w io.Writer, fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}

	ids := []int64{}
	for _, arg := range fs.Args() {
		id, err := strconv.ParseInt(arg, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: %s", errWrongUsage, err)
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		if err := rpcRestartOne(ctx, id); err != nil {
			fmt.Fprintln(w, err)
		}
	}

	// Mainly to allow scripts to touch the database directly.
	if len(ids) == 0 {
		notifierAwaken()
		executorAwaken()
	}
	return nil
}

func rpcReload(ctx context.Context,
	w io.Writer, fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errWrongUsage
	}
	return loadConfig()
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

var rpcCommands = map[string]struct {
	// handler must not write anything when returning an error.
	handler  func(context.Context, io.Writer, *flag.FlagSet, []string) error
	usage    string
	function string
}{
	"enqueue": {rpcEnqueue, "OWNER REPO REF [RUNNER]...",
		"Create or restart tasks for the given reference."},
	"restart": {rpcRestart, "[ID]...",
		"Schedule tasks with the given IDs to be rerun."},
	"reload": {rpcReload, "",
		"Reload configuration."},
}

func rpcPrintCommands(w io.Writer) {
	// The alphabetic ordering is unfortunate, but tolerable.
	keys := []string{}
	for key := range rpcCommands {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	fmt.Fprintf(w, "Commands:\n")
	for _, key := range keys {
		cmd := rpcCommands[key]
		fmt.Fprintf(w, "  %s [OPTION...] %s\n    \t%s\n",
			key, cmd.usage, cmd.function)
	}
}

func handleRPC(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w,
			"Error reading request body", http.StatusInternalServerError)
		return
	}
	if r.Header.Get(rpcHeaderSignature) != giteaSign(body) {
		http.Error(w,
			"Signature mismatch", http.StatusBadRequest)
		return
	}

	var args []string
	if err := json.Unmarshal(body, &args); err != nil {
		http.Error(w,
			"Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(args) == 0 {
		http.Error(w, "Missing command", http.StatusBadRequest)
		return
	}

	// Our handling closely follows what the flag package does internally.

	command, args := args[0], args[1:]
	cmd, ok := rpcCommands[command]
	if !ok {
		http.Error(w, "unknown command: "+command, http.StatusBadRequest)
		rpcPrintCommands(w)
		return
	}

	// If we redirected the FlagSet straight to the response,
	// we would be unable to set our own HTTP status.
	b := bytes.NewBuffer(nil)

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(b)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(),
			"Usage: %s [OPTION...] %s\n%s\n",
			fs.Name(), cmd.usage, cmd.function)
		fs.PrintDefaults()
	}

	err = cmd.handler(r.Context(), w, fs, args)

	// Wrap this error to make it as if fs.Parse discovered the issue.
	if errors.Is(err, errWrongUsage) {
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
	}

	// The flag package first prints all errors that it returns.
	// If the buffer ends up not being empty, flush it into the request.
	if b.Len() != 0 {
		http.Error(w, strings.TrimSpace(b.String()), http.StatusBadRequest)
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	}
}

// --- Notifier ----------------------------------------------------------------

func notifierRunCommand(ctx context.Context, task Task) {
	script := bytes.NewBuffer(nil)
	if err := getConfig().notifyTemplate.Execute(script, &task); err != nil {
		log.Printf("error: notify: %s", err)
		return
	}

	cmd := exec.CommandContext(ctx, "sh")
	cmd.Stdin = script
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("error: notify: %s", err)
	}
}

func notifierNotify(ctx context.Context, task Task) error {
	// Loosely assuming that this only runs on state changes.
	if task.State != taskStateNew && task.State != taskStateRunning {
		go notifierRunCommand(ctx, task)
	}

	payload := struct {
		Context     string `json:"context"`
		Description string `json:"description"`
		State       string `json:"state"`
		TargetURL   string `json:"target_url"`
	}{}

	config := getConfig()
	runner, ok := config.Runners[task.Runner]
	if !ok {
		log.Printf("task %d has an unknown runner %s\n", task.ID, task.Runner)
		return nil
	}
	payload.Context = runner.Name
	payload.TargetURL = fmt.Sprintf("%s/task/%d", config.Root, task.ID)

	switch task.State {
	case taskStateNew:
		payload.State, payload.Description = "pending", "Pending"
	case taskStateRunning:
		payload.State, payload.Description = "pending", "Running"
	case taskStateError:
		payload.State, payload.Description = "error", "Error"
	case taskStateFailed:
		payload.State, payload.Description = "failure", "Failure"
	case taskStateSuccess:
		payload.State, payload.Description = "success", "Success"
	default:
		log.Printf("task %d is in unknown state %d\n", task.ID, task.State)
		return nil
	}

	// We should only fill this in case we have some specific information.
	if task.Detail != "" {
		payload.Description = task.Detail
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	log.Printf("task %d for %s: notifying: %s: %s: %s (%s)\n",
		task.ID, task.FullName(), task.Hash,
		payload.Context, payload.State, payload.Description)

	req, err := giteaNewRequest(ctx, http.MethodPost, fmt.Sprintf(
		"/api/v1/repos/%s/%s/statuses/%s",
		url.PathEscape(task.Owner),
		url.PathEscape(task.Repo),
		url.PathEscape(task.Hash)), bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	_, err = gDB.ExecContext(ctx, `UPDATE task SET notified = 1
		WHERE id = ? AND state = ? AND detail = ? AND notified = 0`,
		task.ID, task.State, task.Detail)
	return err
}

func notifierRun(ctx context.Context) error {
	tasks, err := getTasks(ctx, `WHERE notified = 0 ORDER BY id ASC`)
	if err != nil {
		return err
	}

	for _, task := range tasks {
		if err := notifierNotify(ctx, task); err != nil {
			return fmt.Errorf(
				"task %d for %s: %w", task.ID, task.FullName(), err)
		}
	}
	return nil
}

func notifier(ctx context.Context) {
	for {
		select {
		case <-gNotifierSignal:
		case <-ctx.Done():
			return
		}

		if err := notifierRun(ctx); err != nil {
			log.Printf("error: notifier: %s\n", err)
		}
	}
}

func notifierAwaken() {
	select {
	case gNotifierSignal <- struct{}{}:
	default:
	}
}

// --- Executor ----------------------------------------------------------------
// ~~~ Running task ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// RunningTask stores all data pertaining to a currently running task.
type RunningTask struct {
	DB            Task
	Runner        ConfigRunner
	ProjectRunner ConfigProjectRunner

	RunLog    terminalWriter
	TaskLog   terminalWriter
	DeployLog terminalWriter

	wd         string              // acid working directory
	timeout    time.Duration       // time limit on task execution
	signer     ssh.Signer          // SSH private key
	tmplScript *ttemplate.Template // remote build script
	tmplDeploy *ttemplate.Template // local deployment script
}

// newRunningTask prepares a task for running, without executing anything yet.
func newRunningTask(task Task) (*RunningTask, error) {
	rt := &RunningTask{DB: task}
	config := getConfig()

	// This is for our own tracking, not actually written to database.
	rt.DB.ChangedUnix = time.Now().Unix()

	var ok bool
	rt.Runner, ok = config.Runners[rt.DB.Runner]
	if !ok {
		return nil, fmt.Errorf("unknown runner: %s", rt.DB.Runner)
	}
	project, ok := config.Projects[rt.DB.FullName()]
	if !ok {
		return nil, fmt.Errorf("project configuration not found")
	}
	rt.ProjectRunner, ok = project.Runners[rt.DB.Runner]
	if !ok {
		return nil, fmt.Errorf(
			"project not configured for runner %s", rt.DB.Runner)
	}

	var err error
	if rt.wd, err = os.Getwd(); err != nil {
		return nil, err
	}

	// Lenient or not, some kind of a time limit is desirable.
	rt.timeout = time.Hour
	if rt.ProjectRunner.Timeout != "" {
		rt.timeout, err = time.ParseDuration(rt.ProjectRunner.Timeout)
		if err != nil {
			return nil, fmt.Errorf("timeout: %w", err)
		}
	}

	privateKey, err := os.ReadFile(rt.Runner.SSH.Identity)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot read SSH identity for runner %s: %w", rt.DB.Runner, err)
	}
	rt.signer, err = ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot parse SSH identity for runner %s: %w", rt.DB.Runner, err)
	}

	// The runner setup script may change the working directory,
	// so do everything in one go. However, this approach also makes it
	// difficult to distinguish project-independent runner failures.
	// (For that, we can start multiple ssh.Sessions.)
	//
	// We could pass variables through SSH environment variables,
	// which would require enabling PermitUserEnvironment in sshd_config,
	// or through prepending script lines, but templates are a bit simpler.
	//
	// We let the runner itself clone the repository:
	//  - it is a more flexible in that it can test AUR packages more normally,
	//  - we might have to clone submodules as well.
	// Otherwise, we could download a source archive from Gitea,
	// and use SFTP to upload it to the runner.
	rt.tmplScript, err = ttemplate.New("script").Funcs(shellFuncs).
		Parse(rt.Runner.Setup + "\n" +
			rt.ProjectRunner.Setup + "\n" + rt.ProjectRunner.Build)
	if err != nil {
		return nil, fmt.Errorf("script/build: %w", err)
	}

	rt.tmplDeploy, err = ttemplate.New("deploy").Funcs(shellFuncs).
		Parse(rt.ProjectRunner.Deploy)
	if err != nil {
		return nil, fmt.Errorf("script/deploy: %w", err)
	}

	if os.Getenv("ACID_TERMINAL_DEBUG") != "" {
		base := filepath.Join(executorTmpDir("/tmp"),
			fmt.Sprintf("acid-%d-%s-%s-%s-",
				task.ID, task.Owner, task.Repo, task.Runner))
		rt.RunLog.Tee, _ = os.Create(base + "runlog")
		rt.TaskLog.Tee, _ = os.Create(base + "tasklog")
		// The deployment log should not be interesting.
	}
	return rt, nil
}

func (rt *RunningTask) close() {
	for _, tee := range []io.WriteCloser{
		rt.RunLog.Tee, rt.TaskLog.Tee, rt.DeployLog.Tee} {
		if tee != nil {
			tee.Close()
		}
	}
}

// localEnv creates a process environment for locally run executables.
func (rt *RunningTask) localEnv() []string {
	return append(os.Environ(),
		"ACID_ROOT="+rt.wd,
		"ACID_RUNNER="+rt.DB.Runner,
	)
}

func (rt *RunningTask) elapsed() int64 {
	return int64(time.Since(time.Unix(rt.DB.ChangedUnix, 0)).Seconds())
}

// update stores the running task's state in the database.
func (rt *RunningTask) update() error {
	for _, i := range []struct {
		tw  *terminalWriter
		log *[]byte
	}{
		{&rt.RunLog, &rt.DB.RunLog},
		{&rt.TaskLog, &rt.DB.TaskLog},
		{&rt.DeployLog, &rt.DB.DeployLog},
	} {
		i.tw.Lock()
		defer i.tw.Unlock()
		if *i.log = i.tw.Serialize(0); *i.log == nil {
			*i.log = []byte{}
		}
	}
	rt.DB.DurationSeconds = rt.elapsed()
	return rt.DB.update()
}

// ~~~ Deploy ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func executorDownloadNode(sc *sftp.Client, remotePath, localPath string,
	info os.FileInfo) error {
	if info.IsDir() {
		// Hoping that caller invokes us on parents first.
		return os.MkdirAll(localPath, info.Mode().Perm())
	}

	src, err := sc.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file %s: %w", remotePath, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(
		localPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer dst.Close()

	if _, err = io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy file from remote %s to local %s: %w",
			remotePath, localPath, err)
	}
	return nil
}

func executorDownload(client *ssh.Client, remoteRoot, localRoot string) error {
	sc, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sc.Close()

	walker := sc.Walk(remoteRoot)
	for walker.Step() {
		if walker.Err() != nil {
			return walker.Err()
		}
		relativePath, err := filepath.Rel(remoteRoot, walker.Path())
		if err != nil {
			return err
		}
		if err = executorDownloadNode(sc, walker.Path(),
			filepath.Join(localRoot, relativePath), walker.Stat()); err != nil {
			return err
		}
	}
	return nil
}

func executorLocalShell() string {
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}
	// The os/user package doesn't store the parsed out shell field.
	return "/bin/sh"
}

func executorTmpDir(fallback string) string {
	// See also: https://systemd.io/TEMPORARY_DIRECTORIES/
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		return tmp
	}
	return fallback
}

func executorDeploy(
	ctx context.Context, client *ssh.Client, rt *RunningTask) error {
	script := bytes.NewBuffer(nil)
	if err := rt.tmplDeploy.Execute(script, &rt.DB); err != nil {
		return &executorError{"Deploy template failed", err}
	}

	// Thus the deployment directory must exist iff the script is not empty.
	if script.Len() == 0 {
		return nil
	}

	// We expect the files to be moved elsewhere on the filesystem,
	// and they may get very large, so avoid /tmp.
	dir := filepath.Join(executorTmpDir("/var/tmp"), "acid-deploy")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		return err
	}

	// The passed remoteRoot is relative to sc.Getwd.
	if err := executorDownload(client, "acid-deploy", dir); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, executorLocalShell(), "-c", script.String())
	cmd.Env = rt.localEnv()
	cmd.Dir = dir
	cmd.Stdout = &rt.DeployLog
	cmd.Stderr = &rt.DeployLog
	return cmd.Run()
}

// ~~~ Build ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func executorBuild(
	ctx context.Context, client *ssh.Client, rt *RunningTask) error {
	// This is here to fail early, though logically it is misplaced.
	script := bytes.NewBuffer(nil)
	if err := rt.tmplScript.Execute(script, &rt.DB); err != nil {
		return &executorError{"Script template failed", err}
	}

	session, err := client.NewSession()
	if err != nil {
		return &executorError{"SSH failure", err}
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0}
	if err := session.RequestPty("dumb", 24, 80, modes); err != nil {
		return &executorError{"SSH failure", err}
	}

	log.Printf("task %d for %s: connected\n", rt.DB.ID, rt.DB.FullName())

	session.Stdout = &rt.TaskLog
	session.Stderr = &rt.TaskLog

	// Although passing the script directly takes away the option to specify
	// a particular shell (barring here-documents!), it is simple and reliable.
	//
	// Passing the script over Stdin to sh tended to end up with commands
	// eating the script during processing, and resulted in a hang,
	// because closing the Stdin does not result in remote processes
	// getting a stream of EOF.
	//
	// Piping the script into `cat | sh` while appending a ^D to the end of it
	// appeared to work, but it seems likely that commands might still steal
	// script bytes from the cat program if they choose to read from the tty
	// and the script is longer than the buffer.
	chSession := make(chan error, 1)
	go func() {
		chSession <- session.Run(script.String())
		close(chSession)
	}()

	select {
	case <-ctx.Done():
		// Either shutdown, or early runner termination.
		// The runner is not supposed to finish before the session.
		err = context.Cause(ctx)
	case err = <-chSession:
		// Killing a runner may perfectly well trigger this first,
		// in particular when it's on the same machine.
	}
	return err
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// executorError describes a taskStateError.
type executorError struct {
	Detail string
	Err    error
}

func (e *executorError) Unwrap() error { return e.Err }
func (e *executorError) Error() string {
	return fmt.Sprintf("%s: %s", e.Detail, e.Err)
}

func executorConnect(
	ctx context.Context, config *ssh.ClientConfig, address string) (
	*ssh.Client, error) {
	deadline := time.Now().Add(3 * time.Minute)
	ctxDeadlined, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var d net.Dialer
	for {
		// net.DNSError eats the cause, as in it cannot be unwrapped
		// and tested for a particular subtype.
		conn, err := d.DialContext(ctxDeadlined, "tcp", address)
		if e := ctxDeadlined.Err(); e != nil {
			// This may provide a little bit more information.
			if err != nil {
				return nil, err
			}
			return nil, e
		}
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		// We ignore the parent context, but at least we try.
		conn.SetDeadline(deadline)
		sc, chans, reqs, err := ssh.NewClientConn(conn, address, config)
		conn.SetDeadline(time.Time{})

		// cloud-init-enabled machines, such as OpenBSD,
		// may have a race condition between sshd starting for the first time,
		// and having a configured user.
		//
		// Authentication may therefore regularly fail,
		// and we need to ignore all errors whatsoever,
		// not just spurious partial successes resulting in RST or FIN.
		var neterr net.Error
		if errors.As(err, &neterr) || errors.Is(err, io.EOF) || err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		return ssh.NewClient(sc, chans, reqs), nil
	}
}

func executorRunTask(ctx context.Context, task Task) error {
	rt, err := newRunningTask(task)
	if err != nil {
		task.DurationSeconds = 0
		task.State, task.Detail = taskStateError, "Misconfigured"
		task.Notified = 0
		task.RunLog = []byte(err.Error())
		task.TaskLog = []byte{}
		task.DeployLog = []byte{}
		return task.update()
	}
	defer rt.close()

	ctx, cancelTimeout := context.WithTimeout(ctx, rt.timeout)
	defer cancelTimeout()

	// RunningTasks can be concurrently accessed by HTTP handlers.
	locked := func(f func()) {
		gRunningMutex.Lock()
		defer gRunningMutex.Unlock()
		f()
	}
	locked(func() {
		rt.DB.DurationSeconds = 0
		rt.DB.State, rt.DB.Detail = taskStateRunning, ""
		rt.DB.Notified = 0
		rt.DB.RunLog = []byte{}
		rt.DB.TaskLog = []byte{}
		rt.DB.DeployLog = []byte{}
		gRunning[rt.DB.ID] = rt
	})
	defer locked(func() {
		delete(gRunning, rt.DB.ID)
	})
	if err := rt.update(); err != nil {
		return fmt.Errorf("SQL: %w", err)
	}

	// Errors happening while trying to write an error are unfortunate,
	// but not important enough to abort entirely.
	setError := func(detail string) {
		rt.DB.State, rt.DB.Detail = taskStateError, detail
		if err := rt.update(); err != nil {
			log.Printf("error: task %d for %s: SQL: %s",
				rt.DB.ID, rt.DB.FullName(), err)
		}
	}

	cmd := exec.CommandContext(ctx, rt.Runner.Run)
	cmd.Env = rt.localEnv()

	// Pushing the runner into a new process group that can be killed at once
	// with all its children isn't bullet-proof, it messes with job control
	// when acid is run from an interactive shell, and it also seems avoidable
	// (use "exec" in runner scripts, so that VMs take over the process).
	// Maybe this is something that could be opt-in.
	/*
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if err == syscall.ESRCH {
				return os.ErrProcessDone
			}
			return err
		}
	*/

	log.Printf("task %d for %s: starting %s\n",
		rt.DB.ID, rt.DB.FullName(), rt.Runner.Name)

	cmd.Stdout = &rt.RunLog
	cmd.Stderr = &rt.RunLog
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(&rt.TaskLog, "%s\n", err)
		locked(func() { setError("Runner failed to start") })
		return err
	}

	ctxRunner, cancelRunner := context.WithCancelCause(ctx)
	defer cancelRunner(context.Canceled)
	go func() {
		if err := cmd.Wait(); err != nil {
			cancelRunner(err)
		} else {
			cancelRunner(errors.New("runner exited successfully but early"))
		}
	}()
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-ctxRunner.Done():
			// This doesn't leave the runner almost any time on our shutdown,
			// but whatever--they're supposed to be ephemeral.
		case <-time.After(5 * time.Second):
		}
		_ = cmd.Cancel()
	}()

	client, err := executorConnect(ctxRunner, &ssh.ClientConfig{
		User:            rt.Runner.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(rt.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, rt.Runner.SSH.Address)
	if err != nil {
		fmt.Fprintf(&rt.TaskLog, "%s\n", err)
		locked(func() { setError("SSH failure") })
		return err
	}
	defer client.Close()

	var (
		ee1 *ssh.ExitError
		ee2 *executorError
	)

	err = executorBuild(ctxRunner, client, rt)
	if err != nil {
		locked(func() {
			if errors.As(err, &ee1) {
				rt.DB.State, rt.DB.Detail = taskStateFailed, "Scripts failed"
				fmt.Fprintf(&rt.TaskLog, "\n%s\n", err)
			} else if errors.As(err, &ee2) {
				rt.DB.State, rt.DB.Detail = taskStateError, ee2.Detail
				fmt.Fprintf(&rt.TaskLog, "\n%s\n", ee2.Err)
			} else {
				rt.DB.State, rt.DB.Detail = taskStateError, ""
				fmt.Fprintf(&rt.TaskLog, "\n%s\n", err)
			}
		})
		return rt.update()
	}

	// This is so that it doesn't stay hanging within the sftp package,
	// which uses context.Background() everywhere.
	go func() {
		<-ctxRunner.Done()
		client.Close()
	}()

	err = executorDeploy(ctxRunner, client, rt)
	locked(func() {
		if err == nil {
			rt.DB.State, rt.DB.Detail = taskStateSuccess, ""
		} else if errors.As(err, &ee1) {
			rt.DB.State, rt.DB.Detail = taskStateFailed, "Deployment failed"
			fmt.Fprintf(&rt.DeployLog, "\n%s\n", err)
		} else if errors.As(err, &ee2) {
			rt.DB.State, rt.DB.Detail = taskStateError, ee2.Detail
			fmt.Fprintf(&rt.DeployLog, "\n%s\n", ee2.Err)
		} else {
			rt.DB.State, rt.DB.Detail = taskStateError, ""
			fmt.Fprintf(&rt.DeployLog, "\n%s\n", err)
		}
	})
	return rt.update()
}

func executorRun(ctx context.Context) error {
	tasks, err := getTasks(ctx, `WHERE state = ? OR state = ? ORDER BY id ASC`,
		taskStateNew, taskStateRunning)
	if err != nil {
		return err
	}

	for _, task := range tasks {
		if err := executorRunTask(ctx, task); err != nil {
			return fmt.Errorf("task %d for %s: %w",
				task.ID, task.FullName(), err)
		}
	}
	return nil
}

func executor(ctx context.Context) {
	for {
		select {
		case <-gExecutorSignal:
		case <-ctx.Done():
			return
		}

		if err := executorRun(ctx); err != nil {
			log.Printf("error: executor: %s\n", err)
		}
	}
}

func executorAwaken() {
	select {
	case gExecutorSignal <- struct{}{}:
	default:
	}
}

// --- Main --------------------------------------------------------------------

type taskState int64

const (
	taskStateNew     taskState = iota // → · pending (queued)
	taskStateRunning                  // → · pending (running)
	taskStateError                    // → ! error (internal issue)
	taskStateFailed                   // → × failure (runner issue)
	taskStateSuccess                  // → ✓ success (runner finished)
)

func (ts taskState) String() string {
	switch ts {
	case taskStateNew:
		return "New"
	case taskStateRunning:
		return "Running"
	case taskStateError:
		return "Error"
	case taskStateFailed:
		return "Failed"
	case taskStateSuccess:
		return "Success"
	default:
		return fmt.Sprintf("%d", ts)
	}
}

// Task mirrors SQL task table records, adding a few convenience methods.
type Task struct {
	ID int64

	Owner  string
	Repo   string
	Hash   string
	Runner string

	// True database names for these are occupied by accessors.
	CreatedUnix     int64
	ChangedUnix     int64
	DurationSeconds int64

	State     taskState
	Detail    string
	Notified  int64
	RunLog    []byte
	TaskLog   []byte
	DeployLog []byte
}

func (t *Task) FullName() string { return t.Owner + "/" + t.Repo }

func (t *Task) RunnerName() string {
	if runner, ok := getConfig().Runners[t.Runner]; !ok {
		return t.Runner
	} else {
		return runner.Name
	}
}

func (t *Task) URL() string {
	return fmt.Sprintf("%s/task/%d", getConfig().Root, t.ID)
}

func (t *Task) RepoURL() string {
	return fmt.Sprintf("%s/%s/%s", getConfig().Gitea, t.Owner, t.Repo)
}

func (t *Task) CommitURL() string {
	return fmt.Sprintf("%s/%s/%s/commit/%s",
		getConfig().Gitea, t.Owner, t.Repo, t.Hash)
}

func (t *Task) CloneURL() string {
	return fmt.Sprintf("%s/%s/%s.git", getConfig().Gitea, t.Owner, t.Repo)
}

func shortDurationString(d time.Duration) string {
	rs := []rune(d.Truncate(time.Second).String())
	for i, r := range rs {
		if !unicode.IsLetter(r) {
			continue
		}
		i++
		for i < len(rs) && unicode.IsLetter(rs[i]) {
			i++
		}
		return string(rs[:i])
	}
	return string(rs)
}

func (t *Task) Created() *time.Time {
	if t.CreatedUnix == 0 {
		return nil
	}
	tt := time.Unix(t.CreatedUnix, 0)
	return &tt
}
func (t *Task) Changed() *time.Time {
	if t.ChangedUnix == 0 {
		return nil
	}
	tt := time.Unix(t.ChangedUnix, 0)
	return &tt
}

func (t *Task) CreatedAgo() string {
	if t.CreatedUnix == 0 {
		return ""
	}
	return shortDurationString(time.Since(*t.Created()))
}

func (t *Task) ChangedAgo() string {
	if t.ChangedUnix == 0 {
		return ""
	}
	return shortDurationString(time.Since(*t.Changed()))
}

func (t *Task) Duration() *time.Duration {
	if t.DurationSeconds == 0 {
		return nil
	}
	td := time.Duration(t.DurationSeconds * int64(time.Second))
	return &td
}

func (t *Task) update() error {
	_, err := gDB.ExecContext(context.Background(),
		`UPDATE task SET changed = unixepoch('now'), duration = ?,
		state = ?, detail = ?, notified = ?,
		runlog = ?, tasklog = ?, deploylog = ? WHERE id = ?`,
		t.DurationSeconds,
		t.State, t.Detail, t.Notified,
		t.RunLog, t.TaskLog, t.DeployLog, t.ID)
	if err == nil {
		notifierAwaken()
	}
	return err
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

const initializeSQL = `
PRAGMA application_id = 0x61636964;          -- "acid" in big endian

CREATE TABLE IF NOT EXISTS task(
	id        INTEGER NOT NULL,  -- unique ID

	owner     TEXT NOT NULL,     -- Gitea username
	repo      TEXT NOT NULL,     -- Gitea repository name
	hash      TEXT NOT NULL,     -- commit hash
	runner    TEXT NOT NULL,     -- the runner to use

	created   INTEGER NOT NULL DEFAULT 0,    -- creation timestamp
	changed   INTEGER NOT NULL DEFAULT 0,    -- last state change timestamp
	duration  INTEGER NOT NULL DEFAULT 0,    -- duration of last run

	state     INTEGER NOT NULL DEFAULT 0,    -- task state
	detail    TEXT    NOT NULL DEFAULT '',   -- task state detail
	notified  INTEGER NOT NULL DEFAULT 0,    -- Gitea knows the state
	runlog    BLOB    NOT NULL DEFAULT x'',  -- combined task runner output
	tasklog   BLOB    NOT NULL DEFAULT x'',  -- combined task SSH output
	deploylog BLOB    NOT NULL DEFAULT x'',  -- deployment output

	PRIMARY KEY (id)
) STRICT;
`

func dbEnsureColumn(tx *sql.Tx, table, column, definition string) error {
	var count int64
	if err := tx.QueryRow(
		`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`,
		table, column).Scan(&count); err != nil {
		return err
	} else if count == 1 {
		return nil
	}

	_, err := tx.Exec(
		`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition)
	return err
}

func dbOpen(path string) error {
	var err error
	gDB, err = sql.Open("sqlite3",
		"file:"+path+"?_foreign_keys=1&_busy_timeout=1000")
	if err != nil {
		return err
	}

	tx, err := gDB.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var version int64
	if err = tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}

	switch version {
	case 0:
		if _, err = tx.Exec(initializeSQL); err != nil {
			return err
		}

		// We had not initially set a database schema version,
		// so we're stuck checking this column even on new databases.
		if err = dbEnsureColumn(tx,
			`task`, `deploylog`, `BLOB NOT NULL DEFAULT x''`); err != nil {
			return err
		}
	case 1:
		if err = dbEnsureColumn(tx,
			`task`, `created`, `INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
		if err = dbEnsureColumn(tx,
			`task`, `changed`, `INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
		if err = dbEnsureColumn(tx,
			`task`, `duration`, `INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	case 2:
		// The next migration goes here, remember to increment the number below.
	}

	if _, err = tx.Exec(
		`PRAGMA user_version = ` + strconv.Itoa(2)); err != nil {
		return err
	}
	return tx.Commit()
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// callRPC forwards command line commands to a running server.
func callRPC(args []string) error {
	body, err := json.Marshal(args)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/rpc", getConfig().Root), bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set(rpcHeaderSignature, giteaSign(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err = io.Copy(os.Stdout, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		os.Exit(1)
	}
	return nil
}

// filterTTY exposes the internal virtual terminal filter.
func filterTTY(path string) {
	var r io.Reader = os.Stdin
	if path != "-" {
		if f, err := os.Open(path); err != nil {
			log.Println(err)
		} else {
			r = f
			defer f.Close()
		}
	}

	var tw terminalWriter
	if _, err := io.Copy(&tw, r); err != nil {
		log.Printf("%s: %s\n", path, err)
	}
	if _, err := os.Stdout.Write(tw.Serialize(0)); err != nil {
		log.Printf("%s: %s\n", path, err)
	}
}

func main() {
	version := flag.Bool("version", false, "show version and exit")
	tty := flag.Bool("tty", false, "run the internal virtual terminal filter")

	flag.Usage = func() {
		f := flag.CommandLine.Output()
		fmt.Fprintf(f,
			"Usage: %s [OPTION]... CONFIG [COMMAND...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	if *version {
		fmt.Printf("%s %s\n", projectName, projectVersion)
		return
	}
	if *tty {
		for _, path := range flag.Args() {
			filterTTY(path)
		}
		return
	}

	gConfigPath = flag.Arg(0)
	if err := loadConfig(); err != nil {
		log.Fatalln(err)
	}
	if flag.NArg() > 1 {
		if err := callRPC(flag.Args()[1:]); err != nil {
			log.Fatalln(err)
		}
		return
	}

	if err := dbOpen(getConfig().DB); err != nil {
		log.Fatalln(err)
	}
	defer gDB.Close()

	var wg sync.WaitGroup
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)

	server := &http.Server{Addr: getConfig().Listen}
	http.HandleFunc("/{$}", handleTasks)
	http.HandleFunc("/task/{id}", handleTask)
	http.HandleFunc("/push", handlePush)
	http.HandleFunc("/rpc", handleRPC)

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", server.Addr)
	if err != nil {
		log.Fatalln(err)
	}

	notifierAwaken()
	wg.Add(1)
	go func() {
		defer wg.Done()
		notifier(ctx)
	}()

	executorAwaken()
	wg.Add(1)
	go func() {
		defer wg.Done()
		executor(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop()
		if err := server.Serve(ln); err != http.ErrServerClosed {
			log.Println(err)
		}
	}()

	// Wait until we either receive a signal, or get a server failure.
	<-ctx.Done()
	log.Println("shutting down")

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			log.Println(err)
		}
	}()

	// Repeated signal deliveries during shutdown assume default behaviour.
	// This might or might not be desirable.
	stop()
	wg.Wait()
}
