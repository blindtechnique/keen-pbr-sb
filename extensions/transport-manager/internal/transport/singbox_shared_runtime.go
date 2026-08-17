package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const sharedSingBoxRuntimeKey = "sing-box:shared"
const sharedSingBoxTransitionTimeout = 30 * time.Second

type sharedProcess interface {
	PID() int
	Alive() bool
	Done() <-chan struct{}
	Err() error
	Stop(context.Context) error
}

type execSharedProcess struct {
	cmd   *exec.Cmd
	done  chan struct{}
	alive atomic.Bool
	mu    sync.Mutex
	err   error
}

func startExecSharedProcess(binary, configPath, logPath string) (sharedProcess, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary, "run", "-c", configPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	process := &execSharedProcess{cmd: cmd, done: make(chan struct{})}
	process.alive.Store(true)
	go func() {
		err := cmd.Wait()
		_ = logFile.Close()
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		process.alive.Store(false)
		close(process.done)
	}()
	return process, nil
}

func (p *execSharedProcess) PID() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *execSharedProcess) Alive() bool {
	return p != nil && p.alive.Load()
}

func (p *execSharedProcess) Done() <-chan struct{} {
	return p.done
}

func (p *execSharedProcess) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *execSharedProcess) Stop(ctx context.Context) error {
	if p == nil || !p.Alive() {
		return nil
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		_ = p.cmd.Process.Kill()
		return ctx.Err()
	case <-time.After(5 * time.Second):
		killErr := p.cmd.Process.Kill()
		select {
		case <-p.done:
			return nil
		case <-time.After(time.Second):
		}
		if killErr != nil {
			return fmt.Errorf("kill shared sing-box after shutdown timeout: %w", killErr)
		}
		return errors.New("shared sing-box did not exit after kill")
	}
}

type sharedRuntimeHooks struct {
	checkConfig      func(context.Context, string, string) error
	startProcess     func(string, string, string) (sharedProcess, error)
	interfaceByName  func(string) (*net.Interface, error)
	ensureRules      func([]TransportSpec) error
	rulesPresent     func([]TransportSpec) bool
	removeRules      func(map[string]bool, map[string]TransportSpec)
	removeCrashRules func(map[string]bool, map[string]TransportSpec)
	now              func() time.Time
	startupGrace     time.Duration
}

func defaultSharedRuntimeHooks() sharedRuntimeHooks {
	return sharedRuntimeHooks{
		checkConfig: func(ctx context.Context, binary, path string) error {
			command := exec.CommandContext(ctx, binary, "check", "-c", path)
			if output, err := command.CombinedOutput(); err != nil {
				return fmt.Errorf("sing-box config check: %w: %s", err, string(output))
			}
			return nil
		},
		startProcess:    startExecSharedProcess,
		interfaceByName: net.InterfaceByName,
		ensureRules:     ensureForwardingRulesForSpecs,
		rulesPresent: func(specs []TransportSpec) bool {
			for _, spec := range specs {
				if !forwardingRulesPresent(spec.Interface) {
					return false
				}
			}
			return true
		},
		removeRules:      removeForwardingRulesForTags,
		removeCrashRules: removeOwnedForwardingRulesForTags,
		now:              func() time.Time { return time.Now().UTC() },
		startupGrace:     500 * time.Millisecond,
	}
}

// SharedSingBoxGroup owns the only sing-box process in shared mode. Logical
// transports never manipulate the process directly: every inventory or
// desired-state change is serialized here and either commits as a whole or
// restores the last running configuration.
type SharedSingBoxGroup struct {
	opMu sync.Mutex
	mu   sync.RWMutex

	binary         string
	runtimeDir     string
	healthEndpoint RoutingHealthEndpoint
	hooks          sharedRuntimeHooks

	specs         map[string]TransportSpec
	desired       map[string]bool
	activeTags    map[string]bool
	activeData    []byte
	process       sharedProcess
	state         State
	lastErr       string
	updated       time.Time
	memberUpdated map[string]time.Time
	generation    uint64
}

func NewSharedSingBoxGroup(
	specs []TransportSpec,
	binary string,
	runtimeDir string,
	health RoutingHealthEndpoint,
) (*SharedSingBoxGroup, error) {
	return newSharedSingBoxGroup(specs, binary, runtimeDir, health, defaultSharedRuntimeHooks())
}

func newSharedSingBoxGroup(
	specs []TransportSpec,
	binary string,
	runtimeDir string,
	health RoutingHealthEndpoint,
	hooks sharedRuntimeHooks,
) (*SharedSingBoxGroup, error) {
	if hooks.checkConfig == nil || hooks.startProcess == nil ||
		hooks.interfaceByName == nil || hooks.ensureRules == nil ||
		hooks.rulesPresent == nil ||
		hooks.removeRules == nil || hooks.removeCrashRules == nil ||
		hooks.now == nil {
		return nil, errors.New("shared sing-box runtime hooks must be complete")
	}
	now := hooks.now()
	group := &SharedSingBoxGroup{
		binary: binary, runtimeDir: runtimeDir, healthEndpoint: health, hooks: hooks,
		specs: make(map[string]TransportSpec), desired: make(map[string]bool),
		activeTags: make(map[string]bool), state: StateDown, updated: now,
		memberUpdated: make(map[string]time.Time),
	}
	if err := group.setInitialInventory(specs); err != nil {
		return nil, err
	}
	return group, nil
}

func (g *SharedSingBoxGroup) setInitialInventory(specs []TransportSpec) error {
	if err := ValidateUniqueTunAddresses(specs); err != nil {
		return err
	}
	for _, spec := range specs {
		if !isManagedSingBoxSpec(spec) {
			continue
		}
		if err := ValidateTransportSpec(spec); err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		if _, err := NewSingBox(spec, g.binary, g.runtimeDir, g.healthEndpoint); err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		if _, exists := g.specs[spec.Tag]; exists {
			return fmt.Errorf("transport %q already exists", spec.Tag)
		}
		g.specs[spec.Tag] = cloneTransportSpec(spec)
		g.desired[spec.Tag] = spec.AutoStart
		g.memberUpdated[spec.Tag] = g.updated
	}
	return nil
}

func isManagedSingBoxSpec(spec TransportSpec) bool {
	return spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality"
}

func cloneTransportSpec(spec TransportSpec) TransportSpec {
	spec.BootstrapDNS = append([]string(nil), spec.BootstrapDNS...)
	if spec.VLESS != nil {
		copyVLESS := *spec.VLESS
		spec.VLESS = &copyVLESS
	}
	return spec
}

func (g *SharedSingBoxGroup) Member(tag string) (Transport, error) {
	g.mu.RLock()
	spec, exists := g.specs[tag]
	g.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("transport %q is not a shared sing-box transport", tag)
	}
	return &SharedSingBoxMember{group: g, tag: spec.Tag}, nil
}

func (g *SharedSingBoxGroup) Inventory() []TransportSpec {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return specsFromMap(g.specs)
}

func specsFromMap(values map[string]TransportSpec) []TransportSpec {
	result := make([]TransportSpec, 0, len(values))
	for _, spec := range values {
		result = append(result, cloneTransportSpec(spec))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Tag < result[j].Tag })
	return result
}

func desiredSpecs(specs map[string]TransportSpec, desired map[string]bool) []TransportSpec {
	result := make([]TransportSpec, 0, len(specs))
	for tag, spec := range specs {
		if desired[tag] {
			result = append(result, cloneTransportSpec(spec))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Tag < result[j].Tag })
	return result
}

func (g *SharedSingBoxGroup) ValidateInventory(ctx context.Context, specs []TransportSpec) error {
	managed := make([]TransportSpec, 0, len(specs))
	for _, spec := range specs {
		if isManagedSingBoxSpec(spec) {
			managed = append(managed, cloneTransportSpec(spec))
		}
	}
	if len(managed) == 0 {
		return nil
	}
	config, err := BuildSharedSingBoxConfig(managed)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode shared sing-box config: %w", err)
	}
	return g.checkData(ctx, data)
}

func (g *SharedSingBoxGroup) checkData(ctx context.Context, data []byte) error {
	if err := os.MkdirAll(g.runtimeDir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(g.runtimeDir, ".shared-check-*.json")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return g.hooks.checkConfig(ctx, g.binary, path)
}

// ApplyInventory validates the complete managed inventory and commits it with
// the process transition. Existing manual desired state is preserved, while a
// newly created transport inherits auto_start. Failure leaves both inventory
// and the previously running process untouched.
func (g *SharedSingBoxGroup) ApplyInventory(ctx context.Context, all []TransportSpec) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()

	if err := g.ValidateInventory(ctx, all); err != nil {
		return err
	}
	nextSpecs := make(map[string]TransportSpec)
	for _, spec := range all {
		if isManagedSingBoxSpec(spec) {
			nextSpecs[spec.Tag] = cloneTransportSpec(spec)
		}
	}
	g.mu.RLock()
	nextDesired := make(map[string]bool, len(nextSpecs))
	for tag, spec := range nextSpecs {
		desired, existed := g.desired[tag]
		if !existed {
			desired = spec.AutoStart
		} else if previous, present := g.specs[tag]; present &&
			previous.AutoStart != spec.AutoStart {
			desired = spec.AutoStart
		}
		nextDesired[tag] = desired
	}
	g.mu.RUnlock()
	return g.transitionLocked(ctx, nextSpecs, nextDesired, false)
}

func (g *SharedSingBoxGroup) setDesired(ctx context.Context, tag string, desired bool) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.mu.RLock()
	if _, exists := g.specs[tag]; !exists {
		g.mu.RUnlock()
		return fmt.Errorf("transport %q not found", tag)
	}
	nextSpecs := cloneSpecMap(g.specs)
	nextDesired := cloneBoolMap(g.desired)
	g.mu.RUnlock()
	nextDesired[tag] = desired
	return g.transitionLocked(ctx, nextSpecs, nextDesired, false)
}

func (g *SharedSingBoxGroup) Restart(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.mu.RLock()
	nextSpecs := cloneSpecMap(g.specs)
	nextDesired := cloneBoolMap(g.desired)
	g.mu.RUnlock()
	return g.transitionLocked(ctx, nextSpecs, nextDesired, true)
}

func (g *SharedSingBoxGroup) RestartTag(ctx context.Context, tag string) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.mu.RLock()
	if _, exists := g.specs[tag]; !exists {
		g.mu.RUnlock()
		return fmt.Errorf("transport %q not found", tag)
	}
	nextSpecs := cloneSpecMap(g.specs)
	nextDesired := cloneBoolMap(g.desired)
	g.mu.RUnlock()
	nextDesired[tag] = true
	return g.transitionLocked(ctx, nextSpecs, nextDesired, true)
}

func (g *SharedSingBoxGroup) Reconcile(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.mu.RLock()
	nextSpecs := cloneSpecMap(g.specs)
	nextDesired := cloneBoolMap(g.desired)
	g.mu.RUnlock()
	return g.transitionLocked(ctx, nextSpecs, nextDesired, false)
}

func cloneSpecMap(values map[string]TransportSpec) map[string]TransportSpec {
	result := make(map[string]TransportSpec, len(values))
	for tag, spec := range values {
		result[tag] = cloneTransportSpec(spec)
	}
	return result
}

func cloneBoolMap(values map[string]bool) map[string]bool {
	result := make(map[string]bool, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func (g *SharedSingBoxGroup) transitionLocked(
	ctx context.Context,
	nextSpecs map[string]TransportSpec,
	nextDesired map[string]bool,
	force bool,
) error {
	wanted := desiredSpecs(nextSpecs, nextDesired)
	if len(wanted) == 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		lifecycleCtx, cancelLifecycle := context.WithTimeout(
			context.Background(),
			sharedSingBoxTransitionTimeout,
		)
		defer cancelLifecycle()
		g.mu.Lock()
		process := g.process
		if process != nil {
			g.process = nil
			g.generation++
		}
		g.mu.Unlock()
		if process != nil {
			if err := process.Stop(lifecycleCtx); err != nil && process.Alive() {
				g.mu.Lock()
				g.process = process
				g.state = StateUp
				g.lastErr = ""
				g.updated = g.hooks.now()
				g.generation++
				g.mu.Unlock()
				g.watch(process)
				return fmt.Errorf("stop shared sing-box: %w", err)
			}
		}
		g.removeRulesForActive()
		g.commitState(nextSpecs, nextDesired, nil, nil, map[string]bool{}, StateDown, "")
		return nil
	}

	config, err := BuildSharedSingBoxConfig(wanted)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode shared sing-box config: %w", err)
	}

	g.mu.RLock()
	currentProcess := g.process
	sameConfig := bytes.Equal(data, g.activeData)
	currentHealthy := currentProcess != nil && currentProcess.Alive() &&
		g.interfacesPresent(wanted)
	currentData := append([]byte(nil), g.activeData...)
	currentActiveTags := cloneBoolMap(g.activeTags)
	g.mu.RUnlock()
	if !force && sameConfig && currentHealthy {
		if err := g.ensureRulesFor(wanted); err != nil {
			return err
		}
		g.commitState(
			nextSpecs,
			nextDesired,
			currentProcess,
			currentData,
			currentActiveTags,
			StateUp,
			"",
		)
		return nil
	}

	// Always validate the exact active subset before disturbing the live
	// process. CRUD validates the complete inventory separately, but inactive
	// transports may make that config differ from the one actually started.
	if err := g.checkData(ctx, data); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	g.mu.RLock()
	oldData := append([]byte(nil), g.activeData...)
	oldTags := cloneBoolMap(g.activeTags)
	oldProcess := g.process
	oldSpecs := cloneSpecMap(g.specs)
	oldDesired := cloneBoolMap(g.desired)
	g.mu.RUnlock()

	// Once the previous process is signalled, request cancellation must not
	// leave the runtime between generations. Finish the bounded transition (or
	// rollback) independently from the HTTP request lifecycle.
	lifecycleCtx, cancelLifecycle := context.WithTimeout(
		context.Background(),
		sharedSingBoxTransitionTimeout,
	)
	defer cancelLifecycle()

	g.setTransitionStarting(oldDesired, nextDesired)

	if oldProcess != nil {
		// Detach before signalling the child so its watcher cannot classify an
		// intentional replacement as an unexpected crash in the middle of this
		// transaction.
		g.mu.Lock()
		if g.process == oldProcess {
			g.process = nil
			g.generation++
		}
		g.mu.Unlock()
		if err := oldProcess.Stop(lifecycleCtx); err != nil {
			stopErr := fmt.Errorf("stop previous shared sing-box: %w", err)
			if oldProcess.Alive() {
				g.commitState(
					oldSpecs,
					oldDesired,
					oldProcess,
					oldData,
					oldTags,
					StateUp,
					"",
				)
				g.watch(oldProcess)
				return stopErr
			}
			// The process did stop despite reporting an error. Continue with
			// the already validated candidate rather than leaving no runtime.
		}
	}
	g.removeRulesForTags(oldTags, oldSpecs)

	process, err := g.startCandidate(lifecycleCtx, data, wanted)
	if err == nil {
		tags := make(map[string]bool, len(wanted))
		for _, spec := range wanted {
			tags[spec.Tag] = true
		}
		if ruleErr := g.ensureRulesFor(wanted); ruleErr != nil {
			_ = process.Stop(lifecycleCtx)
			g.removeRulesForTags(tags, nextSpecs)
			err = ruleErr
		} else {
			g.commitState(nextSpecs, nextDesired, process, data, tags, StateUp, "")
			g.watch(process)
			return nil
		}
	}

	applyErr := err
	if len(oldData) == 0 || len(oldTags) == 0 {
		_ = os.Remove(filepath.Join(g.runtimeDir, "shared.json"))
		g.commitState(oldSpecs, oldDesired, nil, oldData, oldTags, StateDegraded, applyErr.Error())
		return applyErr
	}
	oldWanted := desiredSpecs(oldSpecs, oldTags)
	rollbackProcess, rollbackErr := g.startCandidate(lifecycleCtx, oldData, oldWanted)
	if rollbackErr != nil {
		joined := errors.Join(
			applyErr,
			fmt.Errorf("restore previous shared sing-box process: %w", rollbackErr),
		)
		g.commitState(oldSpecs, oldDesired, nil, oldData, oldTags, StateDegraded, joined.Error())
		return joined
	}
	if rollbackRuleErr := g.ensureRulesFor(oldWanted); rollbackRuleErr != nil {
		joined := errors.Join(
			applyErr,
			fmt.Errorf("restore previous shared sing-box forwarding rules: %w", rollbackRuleErr),
		)
		g.commitState(
			oldSpecs,
			oldDesired,
			rollbackProcess,
			oldData,
			oldTags,
			StateDegraded,
			joined.Error(),
		)
		g.watch(rollbackProcess)
		return joined
	}
	g.commitState(oldSpecs, oldDesired, rollbackProcess, oldData, oldTags, StateUp, "")
	g.watch(rollbackProcess)
	return fmt.Errorf("shared sing-box update rolled back: %w", applyErr)
}

func (g *SharedSingBoxGroup) startCandidate(
	ctx context.Context,
	data []byte,
	specs []TransportSpec,
) (sharedProcess, error) {
	if err := os.MkdirAll(g.runtimeDir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(g.runtimeDir, "shared.json")
	if err := writeFileAtomic(path, data, 0600); err != nil {
		return nil, err
	}
	process, err := g.hooks.startProcess(
		g.binary,
		path,
		filepath.Join(g.runtimeDir, "shared.log"),
	)
	if err != nil {
		return nil, err
	}
	deadline := time.NewTimer(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	var readySince time.Time
	for {
		if g.interfacesPresent(specs) && process.Alive() {
			if readySince.IsZero() {
				readySince = time.Now()
			}
			if g.hooks.startupGrace <= 0 ||
				time.Since(readySince) >= g.hooks.startupGrace {
				return process, nil
			}
		} else {
			readySince = time.Time{}
		}
		select {
		case <-ctx.Done():
			_ = process.Stop(context.Background())
			return nil, ctx.Err()
		case <-deadline.C:
			_ = process.Stop(context.Background())
			return nil, fmt.Errorf("shared sing-box interfaces did not appear")
		case <-process.Done():
			err := process.Err()
			if err == nil {
				err = errors.New("sing-box exited before shared interfaces appeared")
			}
			return nil, err
		case <-ticker.C:
		}
	}
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".shared-runtime-*.json")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return err
		}
		return os.Rename(temporary, path)
	}
	return nil
}

func (g *SharedSingBoxGroup) interfacesPresent(specs []TransportSpec) bool {
	for _, spec := range specs {
		if _, err := g.hooks.interfaceByName(spec.Interface); err != nil {
			return false
		}
	}
	return true
}

func (g *SharedSingBoxGroup) ensureRulesFor(specs []TransportSpec) error {
	return g.hooks.ensureRules(specs)
}

func ensureForwardingRulesForSpecs(specs []TransportSpec) error {
	interfaces := make([]string, 0, len(specs))
	for _, spec := range specs {
		interfaces = append(interfaces, spec.Interface)
	}
	return systemForwardingRules.ensureInterfaces(interfaces)
}

func (g *SharedSingBoxGroup) EnsureRuntimeRules() error {
	g.mu.RLock()
	specs := desiredSpecs(g.specs, g.desired)
	process := g.process
	g.mu.RUnlock()
	if process == nil || !process.Alive() {
		return nil
	}
	if err := g.ensureRulesFor(specs); err != nil {
		return err
	}
	truncateRuntimeLogFile(filepath.Join(g.runtimeDir, "shared.log"))
	return nil
}

func (g *SharedSingBoxGroup) removeRulesForActive() {
	g.mu.RLock()
	tags := cloneBoolMap(g.activeTags)
	specs := cloneSpecMap(g.specs)
	g.mu.RUnlock()
	g.removeRulesForTags(tags, specs)
}

func (g *SharedSingBoxGroup) removeRulesForTags(tags map[string]bool, specs map[string]TransportSpec) {
	g.hooks.removeRules(tags, specs)
}

func removeForwardingRulesForTags(tags map[string]bool, specs map[string]TransportSpec) {
	for tag := range tags {
		if spec, exists := specs[tag]; exists {
			removeForwardingRules(spec.Interface, true)
		}
	}
}

func removeOwnedForwardingRulesForTags(tags map[string]bool, specs map[string]TransportSpec) {
	for tag := range tags {
		if spec, exists := specs[tag]; exists {
			removeForwardingRules(spec.Interface, false)
		}
	}
}

func (g *SharedSingBoxGroup) commitState(
	specs map[string]TransportSpec,
	desired map[string]bool,
	process sharedProcess,
	data []byte,
	activeTags map[string]bool,
	state State,
	lastErr string,
) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.hooks.now()
	for tag := range unionSpecTags(g.specs, specs) {
		oldSpec, oldExists := g.specs[tag]
		nextSpec, nextExists := specs[tag]
		memberChanged := oldExists != nextExists ||
			(oldExists && nextExists && !reflect.DeepEqual(oldSpec, nextSpec)) ||
			g.desired[tag] != desired[tag] ||
			g.activeTags[tag] != activeTags[tag] ||
			(g.process != process && (g.activeTags[tag] || activeTags[tag])) ||
			((g.state != state || g.lastErr != lastErr) &&
				(g.desired[tag] || desired[tag]))
		if nextExists {
			if memberChanged {
				g.memberUpdated[tag] = now
			} else if _, exists := g.memberUpdated[tag]; !exists {
				g.memberUpdated[tag] = now
			}
		} else {
			delete(g.memberUpdated, tag)
		}
	}
	g.specs = specs
	g.desired = desired
	g.process = process
	g.activeData = append([]byte(nil), data...)
	g.activeTags = activeTags
	g.state = state
	g.lastErr = lastErr
	g.updated = now
	g.generation++
}

func unionSpecTags(left, right map[string]TransportSpec) map[string]struct{} {
	result := make(map[string]struct{}, len(left)+len(right))
	for tag := range left {
		result[tag] = struct{}{}
	}
	for tag := range right {
		result[tag] = struct{}{}
	}
	return result
}

func (g *SharedSingBoxGroup) setTransitionStarting(
	oldDesired map[string]bool,
	nextDesired map[string]bool,
) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.hooks.now()
	g.state = StateStarting
	g.lastErr = ""
	g.updated = now
	for tag := range g.specs {
		if oldDesired[tag] || nextDesired[tag] {
			g.memberUpdated[tag] = now
		}
	}
}

func (g *SharedSingBoxGroup) watch(process sharedProcess) {
	g.mu.RLock()
	generation := g.generation
	g.mu.RUnlock()
	go func() {
		<-process.Done()
		g.opMu.Lock()
		defer g.opMu.Unlock()
		g.mu.Lock()
		if g.process != process || g.generation != generation {
			g.mu.Unlock()
			return
		}
		tags := cloneBoolMap(g.activeTags)
		specs := cloneSpecMap(g.specs)
		now := g.hooks.now()
		g.process = nil
		g.state = StateDegraded
		if err := process.Err(); err != nil {
			g.lastErr = err.Error()
		} else {
			g.lastErr = "shared sing-box exited"
		}
		g.updated = now
		for tag := range tags {
			g.memberUpdated[tag] = now
		}
		g.mu.Unlock()
		g.hooks.removeCrashRules(tags, specs)
	}()
}

func (g *SharedSingBoxGroup) fail(err error) error {
	g.mu.Lock()
	g.state = StateDegraded
	g.lastErr = err.Error()
	now := g.hooks.now()
	g.updated = now
	for tag, desired := range g.desired {
		if desired {
			g.memberUpdated[tag] = now
		}
	}
	g.mu.Unlock()
	return err
}

func (g *SharedSingBoxGroup) HasDesired() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, desired := range g.desired {
		if desired {
			return true
		}
	}
	return false
}

func (g *SharedSingBoxGroup) Healthy() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.HasDesiredLocked() {
		return true
	}
	return g.process != nil && g.process.Alive() &&
		g.state == StateUp && g.interfacesPresent(desiredSpecs(g.specs, g.desired))
}

func (g *SharedSingBoxGroup) HasDesiredLocked() bool {
	for _, desired := range g.desired {
		if desired {
			return true
		}
	}
	return false
}

func (g *SharedSingBoxGroup) Close(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.mu.RLock()
	process := g.process
	g.mu.RUnlock()
	if process != nil {
		g.mu.Lock()
		if g.process == process {
			g.process = nil
			g.generation++
		}
		g.mu.Unlock()
		if err := process.Stop(ctx); err != nil {
			return err
		}
	}
	g.removeRulesForActive()
	g.mu.Lock()
	g.process = nil
	g.state = StateDown
	now := g.hooks.now()
	g.updated = now
	for tag := range g.specs {
		g.memberUpdated[tag] = now
	}
	g.mu.Unlock()
	return nil
}

type SharedSingBoxMember struct {
	group          *SharedSingBoxGroup
	tag            string
	healthMu       sync.Mutex
	healthFailures int
}

func (m *SharedSingBoxMember) Tag() string { return m.tag }

func (m *SharedSingBoxMember) Up(ctx context.Context) error {
	return m.group.setDesired(ctx, m.tag, true)
}

func (m *SharedSingBoxMember) Down(ctx context.Context) error {
	return m.group.setDesired(ctx, m.tag, false)
}

func (m *SharedSingBoxMember) Restart(ctx context.Context) error {
	return m.group.RestartTag(ctx, m.tag)
}

func (m *SharedSingBoxMember) Status(ctx context.Context) Status {
	status := m.group.memberStatus(ctx, m.tag)
	if status.State == StateUp {
		m.applyRoutingHealth(ctx, &status)
	}
	return status
}

func (m *SharedSingBoxMember) EnsureRuntimeRules() error {
	return m.group.EnsureRuntimeRules()
}

func (m *SharedSingBoxMember) LocalRuntimeReady() bool {
	return m.group.localRuntimeReady(m.tag)
}

func (m *SharedSingBoxMember) SupervisorGroup() supervisorGroup {
	return m.group
}

func (g *SharedSingBoxGroup) memberStatus(ctx context.Context, tag string) Status {
	g.mu.RLock()
	spec, exists := g.specs[tag]
	desired := g.desired[tag]
	process := g.process
	state, lastErr, updated := g.state, g.lastErr, g.memberUpdated[tag]
	if updated.IsZero() {
		updated = g.updated
	}
	active := g.activeTags[tag]
	g.mu.RUnlock()
	if !exists {
		return Status{Tag: tag, State: StateDown, UpdatedAt: updated}
	}
	outbound, _ := outboundFromSpec(spec)
	summary := summariseOutbound(outbound)
	server, _ := outbound["server"].(string)
	protocol, _ := outbound["type"].(string)
	status := Status{
		Tag: tag, DisplayName: spec.DisplayName, Type: spec.Type, Interface: spec.Interface,
		Server: server, ServerPort: summary.port, Protocol: protocol, Security: summary.security,
		SNI: summary.sni, Path: summary.path, Network: summary.legacyNetwork,
		State: StateDown, UpdatedAt: updated, DesiredUp: desired,
	}
	if desired && active && process != nil && process.Alive() {
		status.PID = process.PID()
	}
	if desired {
		status.State = state
		status.Error = lastErr
		if state == StateStarting {
			return status
		}
		if !active || process == nil || !process.Alive() {
			status.State = StateDegraded
		} else if _, err := g.hooks.interfaceByName(spec.Interface); err != nil {
			status.State = StateDegraded
			status.Error = fmt.Sprintf("interface %s is unavailable", spec.Interface)
		}
	}
	return status
}

func (g *SharedSingBoxGroup) localRuntimeReady(tag string) bool {
	g.mu.RLock()
	spec, exists := g.specs[tag]
	desired := g.desired[tag]
	active := g.activeTags[tag]
	process := g.process
	state := g.state
	interfaceByName := g.hooks.interfaceByName
	rulesPresent := g.hooks.rulesPresent
	g.mu.RUnlock()
	if !exists || !desired || !active || state != StateUp ||
		process == nil || !process.Alive() ||
		interfaceByName == nil || rulesPresent == nil {
		return false
	}
	if _, err := interfaceByName(spec.Interface); err != nil {
		return false
	}
	return rulesPresent([]TransportSpec{spec})
}

func (m *SharedSingBoxMember) applyRoutingHealth(ctx context.Context, status *Status) {
	m.group.mu.RLock()
	spec, exists := m.group.specs[m.tag]
	endpoint := m.group.healthEndpoint
	m.group.mu.RUnlock()
	if !exists || endpoint.URL == "" {
		return
	}
	probe := &SingBox{spec: spec, healthEndpoint: endpoint}
	verdict, detail, known := probe.routingHealth(ctx)
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	if !known || verdict == "healthy" || verdict == "active" || verdict == "backup" {
		m.healthFailures = 0
		return
	}
	m.healthFailures++
	if m.healthFailures < 3 {
		return
	}
	status.State = StateDegraded
	status.Error = "keen-pbr routing health: " + verdict
	if detail != "" {
		status.Error += ": " + detail
	}
}

type supervisorGroup interface {
	Key() string
	HasDesired() bool
	Healthy() bool
	Reconcile(context.Context) error
	Restart(context.Context) error
	EnsureRuntimeRules() error
}

func (g *SharedSingBoxGroup) Key() string { return sharedSingBoxRuntimeKey }

var _ Transport = (*SharedSingBoxMember)(nil)
var _ supervisorGroup = (*SharedSingBoxGroup)(nil)
