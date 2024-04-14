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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	ttemplate "text/template"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var (
	projectName    = "acid"
	projectVersion = "?"

	gConfig       Config = Config{Listen: ":http"}
	gNotifyScript *ttemplate.Template
	gDB           *sql.DB

	gNotifierSignal = make(chan struct{}, 1)
	gExecutorSignal = make(chan struct{}, 1)

	// The mutex is at least supposed to lock over the tasks as well.
	gRunningMutex sync.Mutex
	gRunning      = make(map[int64]*RunningTask)
)

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
}

type ConfigRunner struct {
	Name  string `yaml:"name"`  // descriptive name
	Run   string `yaml:"run"`   // runner executable
	Setup string `yaml:"setup"` // runner setup script (SSH)
	SSH   struct {
		User     string `yaml:"user"`     // remote username
		Address  string `yaml:"address"`  // TCP host:port
		Identity string `yaml:"identity"` // private key path
	} `yaml:"ssh"` // shell access
}

type ConfigProject struct {
	Runners map[string]ConfigProjectRunner `yaml:"runners"`
}

type ConfigProjectRunner struct {
	Setup string `yaml:"setup"` // project setup script (SSH)
	Build string `yaml:"build"` // project build script (SSH)
}

func parseConfig(path string) error {
	if f, err := os.Open(path); err != nil {
		return err
	} else if err = yaml.NewDecoder(f).Decode(&gConfig); err != nil {
		return err
	}

	var err error
	gNotifyScript, err = ttemplate.New("notify").Parse(gConfig.Notify)
	return err
}

// --- Utilities ---------------------------------------------------------------

func giteaSign(b []byte) string {
	payloadHmac := hmac.New(sha256.New, []byte(gConfig.Secret))
	payloadHmac.Write(b)
	return hex.EncodeToString(payloadHmac.Sum(nil))
}

func giteaNewRequest(ctx context.Context, method, path string, body io.Reader) (
	*http.Request, error) {
	req, err := http.NewRequestWithContext(
		ctx, method, gConfig.Gitea+path, body)
	if req != nil {
		req.Header.Set("Authorization", "token "+gConfig.Token)
		req.Header.Set("Accept", "application/json")
	}
	return req, err
}

func getTasks(ctx context.Context, query string, args ...any) ([]Task, error) {
	rows, err := gDB.QueryContext(ctx, `
		SELECT id, owner, repo, hash, runner,
			state, detail, notified, runlog, tasklog FROM task `+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasks := []Task{}
	for rows.Next() {
		var t Task
		err := rows.Scan(&t.ID, &t.Owner, &t.Repo, &t.Hash, &t.Runner,
			&t.State, &t.Detail, &t.Notified, &t.RunLog, &t.TaskLog)
		if err != nil {
			return nil, err
		}
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
</dl>
{{if .RunLog}}
<h2>Runner log</h2>
<pre>{{printf "%s" .RunLog}}</pre>
{{end}}
{{if .TaskLog}}
<h2>Task log</h2>
<pre>{{printf "%s" .TaskLog}}</pre>
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

		rt.RunLog.mu.Lock()
		defer rt.RunLog.mu.Unlock()
		rt.TaskLog.mu.Lock()
		defer rt.TaskLog.mu.Unlock()

		task.RunLog = rt.RunLog.b
		task.TaskLog = rt.TaskLog.b
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

	stmt, err := tx.Prepare(`INSERT INTO task(owner, repo, hash, runner)
		VALUES (?, ?, ?, ?)`)
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

	project, ok := gConfig.Projects[event.Repository.FullName]
	if !ok {
		// This is okay, don't set any commit statuses.
		fmt.Fprintf(w, "The project is not configured.")
		return
	}

	runners := []string{}
	for name := range project.Runners {
		runners = append(runners, name)
	}
	sort.Strings(runners)

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
	result, err := gDB.ExecContext(ctx, `UPDATE task
		SET state = ?, detail = '', notified = 0 WHERE id = ?`,
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

	project, ok := gConfig.Projects[owner+"/"+repo]
	if !ok {
		return fmt.Errorf("project configuration not found")
	}

	runners := fs.Args()[3:]
	if len(runners) == 0 {
		for runner := range project.Runners {
			runners = append(runners, runner)
		}
	}
	sort.Strings(runners)

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
	if err := gNotifyScript.Execute(script, &task); err != nil {
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

	runner, ok := gConfig.Runners[task.Runner]
	if !ok {
		log.Printf("task %d has an unknown runner %s\n", task.ID, task.Runner)
		return nil
	}
	payload.Context = runner.Name
	payload.TargetURL = fmt.Sprintf("%s/task/%d", gConfig.Root, task.ID)

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

type terminalWriter struct {
	b   []byte
	cur int
	mu  sync.Mutex
}

func (tw *terminalWriter) Write(p []byte) (written int, err error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// Extremely rudimentary emulation of a dumb terminal.
	for _, b := range p {
		// Enough is enough, writing too much is highly suspicious.
		if len(tw.b) > 64<<20 {
			return written, errors.New("too much terminal output")
		}

		switch b {
		case '\b':
			if tw.cur > 0 && tw.b[tw.cur-1] != '\n' {
				tw.cur--
			}
		case '\r':
			for tw.cur > 0 && tw.b[tw.cur-1] != '\n' {
				tw.cur--
			}
		case '\n':
			tw.b = append(tw.b, b)
			tw.cur = len(tw.b)
		default:
			tw.b = append(tw.b[:tw.cur], b)
			tw.cur = len(tw.b)
		}

		if err != nil {
			break
		}
		written += 1
	}
	return
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

type RunningTask struct {
	DB            Task
	Runner        ConfigRunner
	ProjectRunner ConfigProjectRunner

	RunLog  terminalWriter
	TaskLog terminalWriter
}

func executorUpdate(rt *RunningTask) error {
	rt.RunLog.mu.Lock()
	defer rt.RunLog.mu.Unlock()
	rt.DB.RunLog = bytes.Clone(rt.RunLog.b)
	if rt.DB.RunLog == nil {
		rt.DB.RunLog = []byte{}
	}

	rt.TaskLog.mu.Lock()
	defer rt.TaskLog.mu.Unlock()
	rt.DB.TaskLog = bytes.Clone(rt.TaskLog.b)
	if rt.DB.TaskLog == nil {
		rt.DB.TaskLog = []byte{}
	}

	_, err := gDB.ExecContext(context.Background(), `UPDATE task
		SET state = ?, detail = ?, notified = ?, runlog = ?, tasklog = ?
		WHERE id = ?`,
		rt.DB.State, rt.DB.Detail, rt.DB.Notified, rt.DB.RunLog, rt.DB.TaskLog,
		rt.DB.ID)
	if err == nil {
		notifierAwaken()
	}
	return err
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
	rt := &RunningTask{DB: task}

	var ok bool
	rt.Runner, ok = gConfig.Runners[rt.DB.Runner]
	if !ok {
		return fmt.Errorf("unknown runner: %s", rt.DB.Runner)
	}
	project, ok := gConfig.Projects[rt.DB.FullName()]
	if !ok {
		return fmt.Errorf("project configuration not found")
	}
	rt.ProjectRunner, ok = project.Runners[rt.DB.Runner]
	if !ok {
		return fmt.Errorf(
			"project not configured for runner %s", rt.DB.Runner)
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
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
	tmplScript, err := ttemplate.New("script").Parse(rt.Runner.Setup + "\n" +
		rt.ProjectRunner.Setup + "\n" + rt.ProjectRunner.Build)
	if err != nil {
		return fmt.Errorf("script: %w", err)
	}

	privateKey, err := os.ReadFile(rt.Runner.SSH.Identity)
	if err != nil {
		return fmt.Errorf(
			"cannot read SSH identity for runner %s: %w", rt.DB.Runner, err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf(
			"cannot parse SSH identity for runner %s: %w", rt.DB.Runner, err)
	}

	defer func() {
		gRunningMutex.Lock()
		defer gRunningMutex.Unlock()

		delete(gRunning, rt.DB.ID)
	}()
	func() {
		gRunningMutex.Lock()
		defer gRunningMutex.Unlock()

		rt.DB.State, rt.DB.Detail = taskStateRunning, ""
		rt.DB.Notified = 0
		rt.DB.RunLog = []byte{}
		rt.DB.TaskLog = []byte{}
		gRunning[rt.DB.ID] = rt
	}()
	if err := executorUpdate(rt); err != nil {
		return fmt.Errorf("SQL: %w", err)
	}

	// Errors happening while trying to write an error are unfortunate,
	// but not important enough to abort entirely.
	setError := func(detail string) {
		gRunningMutex.Lock()
		defer gRunningMutex.Unlock()

		rt.DB.State, rt.DB.Detail = taskStateError, detail
		if err := executorUpdate(rt); err != nil {
			log.Printf("error: task %d for %s: SQL: %s",
				rt.DB.ID, rt.DB.FullName(), err)
		}
	}

	script := bytes.NewBuffer(nil)
	if err := tmplScript.Execute(script, &rt.DB); err != nil {
		setError("Script template failed")
		return err
	}

	cmd := exec.CommandContext(ctx, rt.Runner.Run)
	cmd.Env = append(
		os.Environ(),
		"ACID_ROOT="+wd,
		"ACID_RUNNER="+rt.DB.Runner,
	)

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
		setError("Runner failed to start")
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
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, rt.Runner.SSH.Address)
	if err != nil {
		fmt.Fprintf(&rt.TaskLog, "%s\n", err)
		setError("SSH failure")
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		fmt.Fprintf(&rt.TaskLog, "%s\n", err)
		setError("SSH failure")
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0}
	if err := session.RequestPty("dumb", 24, 80, modes); err != nil {
		fmt.Fprintf(&rt.TaskLog, "%s\n", err)
		setError("SSH failure")
		return err
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
	case <-ctxRunner.Done():
		// Either shutdown, or early runner termination.
		// The runner is not supposed to finish before the session.
		err = context.Cause(ctxRunner)
	case err = <-chSession:
		// Killing a runner may perfectly well trigger this first,
		// in particular when it's on the same machine.
	}

	gRunningMutex.Lock()
	defer gRunningMutex.Unlock()

	var ee *ssh.ExitError
	if err == nil {
		rt.DB.State, rt.DB.Detail = taskStateSuccess, ""
	} else if errors.As(err, &ee) {
		rt.DB.State, rt.DB.Detail = taskStateFailed, "Scripts failed"
		fmt.Fprintf(&rt.TaskLog, "\n%s\n", err)
	} else {
		rt.DB.State, rt.DB.Detail = taskStateError, ""
		fmt.Fprintf(&rt.TaskLog, "\n%s\n", err)
	}
	return executorUpdate(rt)
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

	State    taskState
	Detail   string
	Notified int64
	RunLog   []byte
	TaskLog  []byte
}

func (t *Task) FullName() string { return t.Owner + "/" + t.Repo }

func (t *Task) RunnerName() string {
	if runner, ok := gConfig.Runners[t.Runner]; !ok {
		return t.Runner
	} else {
		return runner.Name
	}
}

func (t *Task) URL() string {
	return fmt.Sprintf("%s/task/%d", gConfig.Root, t.ID)
}

func (t *Task) RepoURL() string {
	return fmt.Sprintf("%s/%s/%s", gConfig.Gitea, t.Owner, t.Repo)
}

func (t *Task) CommitURL() string {
	return fmt.Sprintf("%s/%s/%s/commit/%s",
		gConfig.Gitea, t.Owner, t.Repo, t.Hash)
}

func (t *Task) CloneURL() string {
	return fmt.Sprintf("%s/%s/%s.git", gConfig.Gitea, t.Owner, t.Repo)
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS task(
	id       INTEGER NOT NULL,  -- unique ID

	owner    TEXT NOT NULL,     -- Gitea username
	repo     TEXT NOT NULL,     -- Gitea repository name
	hash     TEXT NOT NULL,     -- commit hash
	runner   TEXT NOT NULL,     -- the runner to use

	state    INTEGER NOT NULL DEFAULT 0,    -- task state
	detail   TEXT    NOT NULL DEFAULT '',   -- task state detail
	notified INTEGER NOT NULL DEFAULT 0,    -- Gitea knows the state
	runlog   BLOB    NOT NULL DEFAULT x'',  -- combined task runner output
	tasklog  BLOB    NOT NULL DEFAULT x'',  -- combined task SSH output

	PRIMARY KEY (id)
) STRICT;
`

func openDB(path string) error {
	var err error
	gDB, err = sql.Open("sqlite3",
		"file:"+path+"?_foreign_keys=1&_busy_timeout=1000")
	if err != nil {
		return err
	}

	_, err = gDB.Exec(schemaSQL)
	return err
}

// callRPC forwards command line commands to a running server.
func callRPC(args []string) error {
	body, err := json.Marshal(args)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/rpc", gConfig.Root), bytes.NewReader(body))
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

func main() {
	version := flag.Bool("version", false, "show version and exit")

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

	if err := parseConfig(flag.Arg(0)); err != nil {
		log.Fatalln(err)
	}
	if flag.NArg() > 1 {
		if err := callRPC(flag.Args()[1:]); err != nil {
			log.Fatalln(err)
		}
		return
	}

	if err := openDB(gConfig.DB); err != nil {
		log.Fatalln(err)
	}
	defer gDB.Close()

	var wg sync.WaitGroup
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)

	server := &http.Server{Addr: gConfig.Listen}
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
