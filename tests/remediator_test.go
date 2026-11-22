package tests

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/diff"
	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
	"github.com/ER-brocode/cloud-drift-remediator/pkg/remediator"
	"github.com/ER-brocode/cloud-drift-remediator/pkg/scanner"
)

func TestPolicy_ProtectedResourceGuard(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policy.json")
	pol, err := remediator.LoadPolicy(fixturePath)
	if err != nil {
		t.Fatalf("Failed to load policy fixture: %v", err)
	}

	drift := &model.ResourceDrift{
		ResourceID:   "db-production-database-primary",
		ResourceType: model.ResourceType("aws_db_instance"),
		DriftType:    model.DriftTypeMissingInLive,
		Severity:     model.SeverityCritical,
	}

	action, requiresManual, reason := pol.Evaluate(drift)
	if action != model.ActionAlertOnly {
		t.Errorf("Expected protected resource to be downgraded to ALERT_ONLY, got %s", action)
	}
	if !requiresManual {
		t.Errorf("Expected protected resource to strictly require manual approval")
	}
	_ = reason
}

func TestPlanner_BlastRadiusEnforcement(t *testing.T) {
	pol := remediator.DefaultPolicy()
	pol.MaxBlastRadius = 5 // Low limit to test gating

	// Create 4 critical drifts (weight 5 * 4 = 20 > 5)
	var drifts []*model.ResourceDrift
	for i := 0; i < 4; i++ {
		drifts = append(drifts, &model.ResourceDrift{
			ResourceID:   "sg-test",
			ResourceType: model.AWSsecurityGroup,
			Provider:     model.ProviderAWS,
			DriftType:    model.DriftTypeModified,
			Severity:     model.SeverityCritical,
			Differences: []model.FieldDiff{
				{Path: "ingress[0].cidr_blocks", DesiredValue: "10.0.0.0/16", ActualValue: "0.0.0.0/0"},
			},
		})
	}

	report := &model.DriftReport{
		ReportID:     "report-test",
		TotalDrifted: len(drifts),
		Drifts:       drifts,
	}

	planner := remediator.NewPlanner(pol)
	plan, err := planner.GeneratePlan(report, false)
	if err != nil {
		t.Fatalf("Planner error: %v", err)
	}

	if !plan.RequiresApproval {
		t.Errorf("Expected plan exceeding blast radius limit to require approval")
	}
	if plan.BlastRadiusScore <= pol.MaxBlastRadius {
		t.Errorf("Expected blast score %d > max limit %d", plan.BlastRadiusScore, pol.MaxBlastRadius)
	}
}

func TestRemediator_LiveExecutionAndRollback(t *testing.T) {
	ctx := context.Background()

	// Setup mock scanner with drifted live resource
	awsScan := scanner.NewAWSScanner("us-east-1", true)
	liveRes := &model.Resource{
		ID:       "sg-api-gw",
		Type:     model.AWSsecurityGroup,
		Provider: model.ProviderAWS,
		Attributes: map[string]interface{}{
			"description": "Tampered description",
		},
		Tags: map[string]string{},
	}
	awsScan.SeedLiveResource(liveRes)

	multiScanner := scanner.NewMultiCloudScanner()
	multiScanner.RegisterScanner(awsScan)

	desiredRes := &model.Resource{
		ID:       "sg-api-gw",
		Type:     model.AWSsecurityGroup,
		Provider: model.ProviderAWS,
		Attributes: map[string]interface{}{
			"description": "Authoritative IaC description",
		},
		Tags: map[string]string{},
	}

	engine := diff.NewDriftEngine(nil)
	report, err := engine.DetectDrift([]*model.Resource{desiredRes}, []*model.Resource{liveRes})
	if err != nil {
		t.Fatalf("Drift error: %v", err)
	}

	pol := remediator.DefaultPolicy()
	planner := remediator.NewPlanner(pol)
	plan, err := planner.GeneratePlan(report, false)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}

	auditLog := remediator.NewAuditLogger("")
	execOpts := &remediator.ExecutorOptions{
		MaxConcurrentWorkers: 2,
		EnableRollbackOnFail:  true,
		AutoApprove:           true,
	}
	executor := remediator.NewExecutor(multiScanner, auditLog, execOpts)

	// Execute remediation
	if err := executor.Execute(ctx, plan); err != nil {
		t.Fatalf("Executor failed: %v", err)
	}

	// Verify live resource was reconciled to desired state
	reconciled, err := awsScan.FetchResource(ctx, model.AWSsecurityGroup, "sg-api-gw")
	if err != nil {
		t.Fatalf("Failed to fetch reconciled resource: %v", err)
	}

	if reconciled.Attributes["description"] != "Authoritative IaC description" {
		t.Errorf("Expected description 'Authoritative IaC description', got '%v'", reconciled.Attributes["description"])
	}

	// Verify audit trail logged success
	events := auditLog.GetEvents()
	if len(events) == 0 {
		t.Errorf("Expected audit log events, got 0")
	}
	if events[0].Status != model.StatusSucceeded {
		t.Errorf("Expected StatusSucceeded, got %s", events[0].Status)
	}
}

func TestExecutor_CancellationMarksQueuedStepsFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	plan := &model.RemediationPlan{
		PlanID: "cancelled-plan",
		Steps: []*model.RemediationStep{
			{StepID: "step-1", Action: model.ActionUpdate},
			{StepID: "step-2", Action: model.ActionUpdate},
			{StepID: "step-3", Action: model.ActionUpdate},
		},
	}
	executor := remediator.NewExecutor(nil, nil, &remediator.ExecutorOptions{
		MaxConcurrentWorkers: 2,
	})

	if err := executor.Execute(ctx, plan); err == nil {
		t.Fatal("expected cancellation to be reported as an execution error")
	}

	for _, step := range plan.Steps {
		if step.Status != model.StatusFailed {
			t.Errorf("step %s status = %s, want %s", step.StepID, step.Status, model.StatusFailed)
		}
		if step.ErrorMessage != context.Canceled.Error() {
			t.Errorf("step %s error = %q, want %q", step.StepID, step.ErrorMessage, context.Canceled.Error())
		}
	}
}

func TestRemediator_DryRunDoesNotMutate(t *testing.T) {
	ctx := context.Background()

	awsScan := scanner.NewAWSScanner("us-east-1", true)
	liveRes := &model.Resource{
		ID:       "s3-vault",
		Type:     model.AWSs3Bucket,
		Provider: model.ProviderAWS,
		Attributes: map[string]interface{}{
			"acl": "public-read",
		},
	}
	awsScan.SeedLiveResource(liveRes)

	multiScanner := scanner.NewMultiCloudScanner()
	multiScanner.RegisterScanner(awsScan)

	desiredRes := &model.Resource{
		ID:       "s3-vault",
		Type:     model.AWSs3Bucket,
		Provider: model.ProviderAWS,
		Attributes: map[string]interface{}{
			"acl": "private",
		},
	}

	engine := diff.NewDriftEngine(nil)
	report, _ := engine.DetectDrift([]*model.Resource{desiredRes}, []*model.Resource{liveRes})

	planner := remediator.NewPlanner(nil)
	dryRunPlan, _ := planner.GeneratePlan(report, true)

	auditLog := remediator.NewAuditLogger("")
	executor := remediator.NewExecutor(multiScanner, auditLog, nil)

	if err := executor.Execute(ctx, dryRunPlan); err != nil {
		t.Fatalf("Dry run execution failed: %v", err)
	}

	// Ensure live state was NOT modified
	fetched, _ := awsScan.FetchResource(ctx, model.AWSs3Bucket, "s3-vault")
	if fetched.Attributes["acl"] != "public-read" {
		t.Errorf("Expected live ACL to remain 'public-read' in dry-run, got '%v'", fetched.Attributes["acl"])
	}

	if dryRunPlan.Steps[0].Status != model.StatusDryRun {
		t.Errorf("Expected step status StatusDryRun, got %s", dryRunPlan.Steps[0].Status)
	}
}
