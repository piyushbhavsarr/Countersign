package cloud

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

// These tests run the real AWS CLI against a moto server with IAM enforcement on, so the
// view / read / write tiers are decided by IAM policies, not by the test:
//
//	UNDOLAYER_TEST_MOTO=/path/to/moto_server go test ./internal/connectors/cloud
//
// moto enforces IAM after INITIAL_NO_AUTH_ACTION_COUNT requests; setup uses exactly that many.
const setupRequests = 12

const secretValue = "pw-hunter2-moto-prod"

func moto(t *testing.T) (*tx.Manager, func(profile string, args ...string) string) {
	bin := os.Getenv("UNDOLAYER_TEST_MOTO")
	if bin == "" {
		t.Skip("set UNDOLAYER_TEST_MOTO to a moto_server binary to run AWS tests")
	}
	if _, err := exec.LookPath("aws"); err != nil {
		t.Skip("aws CLI not installed")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	srv := exec.Command(bin, "-p", fmt.Sprint(port))
	srv.Env = append(os.Environ(), fmt.Sprintf("INITIAL_NO_AUTH_ACTION_COUNT=%d", setupRequests))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	dir := t.TempDir()
	root := func(args ...string) string {
		cmd := exec.Command("aws", append([]string{"--endpoint-url", endpoint, "--output", "json"}, args...)...)
		cmd.Env = append(os.Environ(), "AWS_ACCESS_KEY_ID=AKIAROOTROOTROOT00", "AWS_SECRET_ACCESS_KEY=root",
			"AWS_DEFAULT_REGION=us-east-1", "AWS_CONFIG_FILE=/dev/null", "AWS_SHARED_CREDENTIALS_FILE=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("setup %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	policies := map[string]string{ // what each tier's IAM policy allows
		"view":  `["ec2:Describe*","sns:ListTopics","s3:ListAllMyBuckets"]`,
		"read":  `["ec2:Describe*","sns:ListTopics","sns:GetTopicAttributes","s3:List*","s3:Get*","secretsmanager:GetSecretValue","secretsmanager:ListSecrets"]`,
		"write": `"*"`,
	}
	var creds, config strings.Builder
	for _, u := range []string{"view", "read", "write"} {
		root("iam", "create-user", "--user-name", u)
		var k struct {
			AccessKey struct{ AccessKeyId, SecretAccessKey string }
		}
		_ = json.Unmarshal([]byte(root("iam", "create-access-key", "--user-name", u)), &k)
		root("iam", "put-user-policy", "--user-name", u, "--policy-name", "tier", "--policy-document",
			fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":%s,"Resource":"*"}]}`, policies[u]))
		fmt.Fprintf(&creds, "[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n", u, k.AccessKey.AccessKeyId, k.AccessKey.SecretAccessKey)
		fmt.Fprintf(&config, "[profile %s]\nregion = us-east-1\nendpoint_url = %s\n", u, endpoint)
	}
	root("secretsmanager", "create-secret", "--name", "prod/db", "--secret-string", secretValue)
	root("s3api", "create-bucket", "--bucket", "customer-exports")
	_ = os.WriteFile(filepath.Join(dir, "rows.csv"), []byte("id,email\n1,a@shop.example\n"), 0o600)
	root("s3api", "put-object", "--bucket", "customer-exports", "--key", "customers-2026-11.csv", "--body", filepath.Join(dir, "rows.csv"))
	_ = os.WriteFile(filepath.Join(dir, "credentials"), []byte(creds.String()), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "config"), []byte(config.String()), 0o600)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_ENDPOINT_URL"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	m, err := tx.NewManager(filepath.Join(dir, "state"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	c := New(filepath.Join(dir, "state"))
	c.ViewProfile, c.ReadProfile = "view", "read"
	m.Register(c)
	as := func(profile string, args ...string) string {
		out, err := exec.Command("aws", append([]string{"--profile", profile, "--output", "json"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("aws %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	return m, as
}

func awsCall(x *tx.Tx, service, action string, params map[string]any) (map[string]any, error) {
	args := map[string]any{"service": service, "action": action}
	if params != nil {
		args["params"] = params
	}
	r, err := x.Call("cloud", "aws", args)
	m, _ := r.(map[string]any)
	return m, err
}

func lastAction(x *tx.Tx) *model.Action { return x.Actions[len(x.Actions)-1] }

func TestAWSTiersAreDecidedByIAM(t *testing.T) {
	m, _ := moto(t)
	x := m.Begin("check the network and the exports")

	// metadata: the view-only user may do it, so it runs now and is not sensitive
	r, err := awsCall(x, "ec2", "DescribeVpcs", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := lastAction(x); a.Effect != model.Read || a.Facts["sensitive_read"] == true {
		t.Fatalf("a metadata read was not a plain read: %v %v", a.Effect, a.Facts)
	}
	if !strings.Contains(fmt.Sprint(r), "Vpcs") {
		t.Fatalf("no result: %v", r)
	}

	// data: view-only is refused by IAM, read-only may: it is a data read, its values sensitive
	if _, err := awsCall(x, "s3api", "ListObjectsV2", map[string]any{"Bucket": "customer-exports"}); err != nil {
		t.Fatal(err)
	}
	if a := lastAction(x); a.Facts["sensitive_read"] != true {
		t.Fatalf("IAM refused view-only, but the read was not treated as data: %v", a.Facts)
	}
	_, _ = x.Rollback("test")
}

func TestSecretValuesNeverReachTheAgent(t *testing.T) {
	m, _ := moto(t)
	x := m.Begin("check the database secret is set")
	r, err := awsCall(x, "secretsmanager", "GetSecretValue", map[string]any{"SecretId": "prod/db"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), secretValue) {
		t.Fatalf("the secret reached the agent: %s", b)
	}
	if !strings.Contains(string(b), "REDACTED") {
		t.Fatalf("no redaction marker: %s", b)
	}
	_, _ = x.Rollback("test")
}

func TestChangesAreHeldUntilApprovedAndRunWithWriteCredentials(t *testing.T) {
	m, as := moto(t)
	topics := func() int {
		var l struct{ Topics []any }
		_ = json.Unmarshal([]byte(as("write", "sns", "list-topics")), &l)
		return len(l.Topics)
	}
	x := m.Begin("create an alerts topic")
	r, err := awsCall(x, "sns", "CreateTopic", map[string]any{"Name": "alerts"})
	if err != nil {
		t.Fatal(err)
	}
	if r["held"] != true || lastAction(x).Facts["mutation"] != true {
		t.Fatalf("IAM refused read-only credentials, but the call was not held as a change: %v", r)
	}
	if topics() != 0 {
		t.Fatal("the change ran before approval")
	}
	var ar *model.ApprovalRequired
	if _, err := x.Commit(); !errors.As(err, &ar) {
		t.Fatalf("committed without approval: %v", err)
	}
	if err := x.Approve("alice", m.ApprovalToken(x.ID, x.PreviewHash())); err != nil {
		t.Fatal(err)
	}
	c, _ := m.Connector("cloud")
	c.(*Connector).WriteProfile = "write"
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if topics() != 1 {
		t.Fatal("the approved change did not run with the write credentials")
	}
}

func TestAnEndpointIgnoringDryRunIsReported(t *testing.T) {
	m, _ := moto(t) // moto, unlike AWS, executes EC2 calls sent with --dry-run
	c, _ := m.Connector("cloud")
	c.(*Connector).WriteProfile = "write"
	x := m.Begin("create a VPC")
	if _, err := awsCall(x, "ec2", "CreateVpc", map[string]any{"CidrBlock": "10.9.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if a := lastAction(x); a.Facts["dry_run_ignored"] != true {
		t.Fatalf("a dry run that succeeded was not reported: %v", a.Facts)
	}
	_, _ = x.Rollback("test")
}
