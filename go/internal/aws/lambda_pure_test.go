package aws

import "testing"

// This file covers lambda.go's pure builder-support functions that had no direct
// tests: isRefShape (0%), updateCodeBody (0%), and envConfig's non-empty branch
// (33.3% — only the "no env" path was exercised elsewhere).

func TestIsRefShape(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"a $ref map", map[string]any{"$ref": map[string]any{"capability": "db", "output": "host"}}, true},
		{"a plain string", "literal", false},
		{"a map with $ref plus another key", map[string]any{"$ref": "x", "other": "y"}, false},
		{"an empty map", map[string]any{}, false},
		{"a map with one non-$ref key", map[string]any{"foo": "bar"}, false},
		{"nil", nil, false},
		{"a number", 42, false},
	}
	for _, c := range cases {
		if got := isRefShape(c.v); got != c.want {
			t.Errorf("isRefShape(%v) [%s] = %v, want %v", c.v, c.name, got, c.want)
		}
	}
}

func TestLambdaPlan_UpdateCodeBody(t *testing.T) {
	p := LambdaPlan{ImageUri: "123.dkr.ecr.eu-central-1.amazonaws.com/app:latest"}
	body := p.updateCodeBody()
	if body["ImageUri"] != p.ImageUri {
		t.Fatalf("updateCodeBody = %+v, want ImageUri=%q", body, p.ImageUri)
	}
	if len(body) != 1 {
		t.Fatalf("updateCodeBody must carry ONLY the image (code, not configuration): %+v", body)
	}
}

func TestLambdaPlan_EnvConfig(t *testing.T) {
	// empty -> nil (no Environment block at all)
	p := LambdaPlan{}
	if env := p.envConfig(); env != nil {
		t.Fatalf("an empty environment must render nil, got %+v", env)
	}
	// non-empty -> a Variables map carrying every entry
	p.Environment = map[string]string{"DB_HOST": "aurora.internal", "LOG_LEVEL": "info"}
	env := p.envConfig()
	if env == nil {
		t.Fatal("a non-empty environment must render a Variables block")
	}
	vars, ok := env["Variables"].(map[string]any)
	if !ok || vars["DB_HOST"] != "aurora.internal" || vars["LOG_LEVEL"] != "info" {
		t.Fatalf("envConfig Variables = %+v", env)
	}
}

func TestLambdaPlan_VpcConfig(t *testing.T) {
	p := LambdaPlan{}
	if vc := p.vpcConfig(); vc != nil {
		t.Fatalf("no subnets/sgs must render nil, got %+v", vc)
	}
	p.Subnets = []string{"subnet-a"}
	if vc := p.vpcConfig(); vc != nil {
		t.Fatalf("subnets without security groups must render nil (partial config), got %+v", vc)
	}
	p.SecurityGroups = []string{"sg-1"}
	vc := p.vpcConfig()
	if vc == nil {
		t.Fatal("both subnets and security groups must render a VpcConfig")
	}
}

func TestCanonSubnetsSGsAndEnv(t *testing.T) {
	if got := canonSubnetsSGs(nil, nil); got != "" {
		t.Fatalf("empty canonSubnetsSGs must be empty, got %q", got)
	}
	got := canonSubnetsSGs([]string{"subnet-b", "subnet-a"}, []string{"sg-2", "sg-1"})
	want := "subnets=subnet-a,subnet-b;sgs=sg-1,sg-2"
	if got != want {
		t.Fatalf("canonSubnetsSGs order-independence: got %q, want %q", got, want)
	}
	if got := canonEnv(nil); got != "" {
		t.Fatalf("empty canonEnv must be empty, got %q", got)
	}
	if got := canonEnv(map[string]string{"B": "2", "A": "1"}); got != "A=1;B=2" {
		t.Fatalf("canonEnv must sort keys, got %q", got)
	}
}

func TestLambdaPlan_OperandCanon(t *testing.T) {
	p := LambdaPlan{
		Subnets: []string{"subnet-a"}, SecurityGroups: []string{"sg-1"},
		Environment: map[string]string{"K": "V"}, ImageUri: "img:latest",
	}
	vpc, env, pkg := p.operandCanon()
	if vpc != "subnets=subnet-a;sgs=sg-1" || env != "K=V" || pkg != "img:latest" {
		t.Fatalf("operandCanon = (%q, %q, %q)", vpc, env, pkg)
	}
}

func TestLambdaPlan_UpdateConfigBody(t *testing.T) {
	p := LambdaPlan{RoleArn: "arn:aws:iam::0:role/x", TimeoutSec: 30}
	body := p.updateConfigBody()
	if body["Role"] != p.RoleArn || body["Timeout"] != 30 {
		t.Fatalf("updateConfigBody = %+v", body)
	}
	// no VpcConfig/Environment set -> DETACHING shape (empty lists/vars, not omitted)
	vc, ok := body["VpcConfig"].(map[string]any)
	if !ok || len(vc["SubnetIds"].([]any)) != 0 || len(vc["SecurityGroupIds"].([]any)) != 0 {
		t.Fatalf("an unattached function must send an EMPTY VpcConfig (to detach), got %+v", vc)
	}
	envBlock, ok := body["Environment"].(map[string]any)
	if !ok {
		t.Fatalf("Environment block missing: %+v", body)
	}
	vars, ok := envBlock["Variables"].(map[string]any)
	if !ok || len(vars) != 0 {
		t.Fatalf("an unset environment must send EMPTY Variables (to clear it), got %+v", envBlock)
	}
}
