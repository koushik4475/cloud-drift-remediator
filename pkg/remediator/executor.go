package remediator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
	"github.com/ER-brocode/cloud-drift-remediator/pkg/scanner"
)

// ExecutorOptions configures concurrency and safety execution behaviors.
type ExecutorOptions struct {
	MaxConcurrentWorkers int
	EnableRollbackOnFail  bool
	WebhookURL            string
	AutoApprove           bool
}

// DefaultExecutorOptions returns production defaults.
func DefaultExecutorOptions() *ExecutorOptions {
	return &ExecutorOptions{
		MaxConcurrentWorkers: 4,
		EnableRollbackOnFail:  true,
		AutoApprove:           false,
	}
}

// Executor processes remediation plans against live cloud providers.
type Executor struct {
	scannerCoordinator *scanner.MultiCloudScanner
	auditLogger        *AuditLogger
	opts               *ExecutorOptions
}

// NewExecutor initializes an execution driver.
func NewExecutor(sc *scanner.MultiCloudScanner, auditLogger *AuditLogger, opts *ExecutorOptions) *Executor {
	if opts == nil {
		opts = DefaultExecutorOptions()
	}
	return &Executor{
		scannerCoordinator: sc,
		auditLogger:        auditLogger,
		opts:               opts,
	}
}

// Execute applies the remediation steps defined in the plan.
func (e *Executor) Execute(ctx context.Context, plan *model.RemediationPlan) error {
	if plan == nil {
		return fmt.Errorf("remediation plan cannot be nil")
	}

	// Safety Gate: Enforce approval requirement
	if plan.RequiresApproval && !plan.Approved && !e.opts.AutoApprove {
		return fmt.Errorf("remediation plan %s requires explicit approval (blast radius score: %d); use --auto-approve or approve through governance portal",
			plan.PlanID, plan.BlastRadiusScore)
	}

	if plan.DryRun {
		for _, step := range plan.Steps {
			step.Status = model.StatusDryRun
			now := time.Now()
			step.ExecutedAt = &now
			if e.auditLogger != nil {
				e.auditLogger.LogEvent(AuditEvent{
					EventID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
					Timestamp:  now,
					PlanID:     plan.PlanID,
					StepID:     step.StepID,
					ResourceID: step.ResourceID,
					Action:     step.Action,
					Status:     model.StatusDryRun,
					Details:    "Dry-run execution simulated; no cloud mutation executed",
				})
			}
		}
		return nil
	}

	// Worker pool execution
	stepChan := make(chan *model.RemediationStep, len(plan.Steps))
	for _, s := range plan.Steps {
		stepChan <- s
	}
	close(stepChan)

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var executionErrors []error

	numWorkers := e.opts.MaxConcurrentWorkers
	if numWorkers <= 0 {
		numWorkers = 1
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for step := range stepChan {
				select {
				case <-ctx.Done():
					cancelErr := ctx.Err()
					step.Status = model.StatusFailed
					step.ErrorMessage = cancelErr.Error()
					errMu.Lock()
					executionErrors = append(executionErrors, fmt.Errorf("step %s cancelled: %w", step.StepID, cancelErr))
					errMu.Unlock()
					// Keep draining the queue so every unstarted step gets a
					// terminal status instead of being left pending.
					continue
				default:
				}

				if err := e.executeStep(ctx, step); err != nil {
					errMu.Lock()
					executionErrors = append(executionErrors, err)
					errMu.Unlock()

					// Attempt rollback if enabled
					if e.opts.EnableRollbackOnFail && step.RollbackPlan != nil {
						_ = e.executeRollback(ctx, step)
					}
				}
			}
		}()
	}

	wg.Wait()

	// Dispatch notification if webhook configured
	if e.opts.WebhookURL != "" {
		_ = e.sendWebhookNotification(plan)
	}

	if len(executionErrors) > 0 {
		return fmt.Errorf("remediation encountered %d errors: %v", len(executionErrors), executionErrors)
	}

	return nil
}

func (e *Executor) executeStep(ctx context.Context, step *model.RemediationStep) error {
	step.Status = model.StatusExecuting
	now := time.Now()
	step.ExecutedAt = &now

	sc, ok := e.scannerCoordinator.GetScanner(step.Provider)
	if !ok {
		err := fmt.Errorf("no live scanner registered for provider %s", step.Provider)
		step.Status = model.StatusFailed
		step.ErrorMessage = err.Error()
		return err
	}

	targetRes := &model.Resource{
		ID:         step.ResourceID,
		Type:       step.ResourceType,
		Provider:   step.Provider,
		Attributes: make(map[string]interface{}),
		Tags:       make(map[string]string),
	}

	var opErr error
	switch step.Action {
	case model.ActionUpdate:
		opErr = sc.UpdateResource(ctx, targetRes, step.TargetChanges)
	case model.ActionDelete:
		opErr = sc.DeleteResource(ctx, targetRes)
	case model.ActionRecreate:
		// First attempt creation
		opErr = sc.CreateResource(ctx, targetRes)
	case model.ActionAlertOnly:
		// Informational step, no cloud action
		step.Status = model.StatusSucceeded
		return nil
	default:
		opErr = fmt.Errorf("unsupported remediation action: %s", step.Action)
	}

	if opErr != nil {
		step.Status = model.StatusFailed
		step.ErrorMessage = opErr.Error()
		if e.auditLogger != nil {
			e.auditLogger.LogEvent(AuditEvent{
				EventID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
				Timestamp:  time.Now(),
				StepID:     step.StepID,
				ResourceID: step.ResourceID,
				Action:     step.Action,
				Status:     model.StatusFailed,
				Details:    opErr.Error(),
			})
		}
		return opErr
	}

	step.Status = model.StatusSucceeded
	if e.auditLogger != nil {
		e.auditLogger.LogEvent(AuditEvent{
			EventID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
			Timestamp:  time.Now(),
			StepID:     step.StepID,
			ResourceID: step.ResourceID,
			Action:     step.Action,
			Status:     model.StatusSucceeded,
			Details:    fmt.Sprintf("Successfully applied %s to %s", step.Action, step.ResourceID),
		})
	}
	return nil
}

func (e *Executor) executeRollback(ctx context.Context, step *model.RemediationStep) error {
	sc, ok := e.scannerCoordinator.GetScanner(step.Provider)
	if !ok {
		return fmt.Errorf("rollback failed: no scanner for provider %s", step.Provider)
	}

	rollback := step.RollbackPlan
	if rollback == nil {
		return nil
	}

	var err error
	switch rollback.Action {
	case model.ActionUpdate:
		var rollbackChanges []model.FieldDiff
		for k, v := range rollback.PreviousState {
			rollbackChanges = append(rollbackChanges, model.FieldDiff{
				Path:         k,
				DesiredValue: v,
			})
		}
		err = sc.UpdateResource(ctx, rollback.TargetResource, rollbackChanges)
	case model.ActionDelete:
		err = sc.DeleteResource(ctx, rollback.TargetResource)
	}

	if err == nil {
		step.Status = model.StatusRolledBack
		if e.auditLogger != nil {
			e.auditLogger.LogEvent(AuditEvent{
				EventID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
				Timestamp:  time.Now(),
				StepID:     step.StepID,
				ResourceID: step.ResourceID,
				Action:     model.ActionRollback,
				Status:     model.StatusRolledBack,
				Details:    "Automated rollback successfully restored original state",
			})
		}
	}
	return err
}

func (e *Executor) sendWebhookNotification(plan *model.RemediationPlan) error {
	payload, err := json.Marshal(map[string]interface{}{
		"text": fmt.Sprintf("Cloud Drift Remediation Plan [%s] Executed: %d steps processed", plan.PlanID, plan.TotalSteps),
		"plan": plan,
	})
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(e.opts.WebhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
