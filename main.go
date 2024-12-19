/*
Copyright 2020 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	flag "github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/fluxcd/pkg/runtime/client"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	feathelper "github.com/fluxcd/pkg/runtime/features"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/leaderelection"
	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/pprof"
	"github.com/fluxcd/pkg/runtime/probes"

	"github.com/fluxcd/source-controller/api/v1"
	"github.com/fluxcd/source-controller/api/v1beta2"

	// +kubebuilder:scaffold:imports

	"github.com/fluxcd/source-controller/internal/controller"
	intdigest "github.com/fluxcd/source-controller/internal/digest"
)

const controllerName = "source-controller"

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(v1beta2.AddToScheme(scheme))
	utilruntime.Must(v1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		metricsAddr              string
		eventsAddr               string
		healthAddr               string
		storagePath              string
		storageAddr              string
		storageAdvAddr           string
		concurrent               int
		requeueDependency        time.Duration
		clientOptions            client.Options
		logOptions               logger.Options
		leaderElectionOptions    leaderelection.Options
		rateLimiterOptions       helper.RateLimiterOptions
		featureGates             feathelper.FeatureGates
		watchOptions             helper.WatchOptions
		intervalJitterOptions    jitter.IntervalOptions
		artifactRetentionTTL     time.Duration
		artifactRetentionRecords int
		artifactDigestAlgo       string
	)

	flag.StringVar(&metricsAddr, "metrics-addr", envOrDefault("METRICS_ADDR", ":8080"),
		"The address the metric endpoint binds to.")
	flag.StringVar(&eventsAddr, "events-addr", envOrDefault("EVENTS_ADDR", ""),
		"The address of the events receiver.")
	flag.StringVar(&healthAddr, "health-addr", ":9440", "The address the health endpoint binds to.")
	flag.StringVar(&storagePath, "storage-path", envOrDefault("STORAGE_PATH", ""),
		"The local storage path.")
	flag.StringVar(&storageAddr, "storage-addr", envOrDefault("STORAGE_ADDR", ":9090"),
		"The address the static file server binds to.")
	flag.StringVar(&storageAdvAddr, "storage-adv-addr", envOrDefault("STORAGE_ADV_ADDR", ""),
		"The advertised address of the static file server.")
	flag.IntVar(&concurrent, "concurrent", 2, "The number of concurrent reconciles per controller.")
	flag.DurationVar(&requeueDependency, "requeue-dependency", 30*time.Second,
		"The interval at which failing dependencies are reevaluated.")
	flag.DurationVar(&artifactRetentionTTL, "artifact-retention-ttl", 60*time.Second,
		"The duration of time that artifacts from previous reconciliations will be kept in storage before being garbage collected.")
	flag.IntVar(&artifactRetentionRecords, "artifact-retention-records", 2,
		"The maximum number of artifacts to be kept in storage after a garbage collection.")
	flag.StringVar(&artifactDigestAlgo, "artifact-digest-algo", intdigest.Canonical.String(),
		"The algorithm to use to calculate the digest of artifacts.")

	clientOptions.BindFlags(flag.CommandLine)
	logOptions.BindFlags(flag.CommandLine)
	leaderElectionOptions.BindFlags(flag.CommandLine)
	rateLimiterOptions.BindFlags(flag.CommandLine)
	featureGates.BindFlags(flag.CommandLine)
	watchOptions.BindFlags(flag.CommandLine)
	intervalJitterOptions.BindFlags(flag.CommandLine)

	flag.Parse()

	logger.SetLogger(logger.NewLogger(logOptions))

	if err := featureGates.WithLogger(setupLog).SupportedFeatures(features.FeatureGates()); err != nil {
		setupLog.Error(err, "unable to load feature gates")
		os.Exit(1)
	}

	if err := intervalJitterOptions.SetGlobalJitter(nil); err != nil {
		setupLog.Error(err, "unable to set global jitter")
		os.Exit(1)
	}

	mgr := mustSetupManager(metricsAddr, healthAddr, concurrent, watchOptions, clientOptions, leaderElectionOptions)

	probes.SetupChecks(mgr, setupLog)

	metrics := helper.NewMetrics(mgr, metrics.MustMakeRecorder(), v1.SourceFinalizer)
	eventRecorder := mustSetupEventRecorder(mgr, eventsAddr, controllerName)
	storage := mustInitStorage(storagePath, storageAdvAddr, artifactRetentionTTL, artifactRetentionRecords, artifactDigestAlgo)

	ctx := ctrl.SetupSignalHandler()

	if err := (&controller.BucketReconciler{
		Client:         mgr.GetClient(),
		EventRecorder:  eventRecorder,
		Metrics:        metrics,
		Storage:        storage,
		ControllerName: controllerName,
	}).SetupWithManagerAndOptions(mgr, controller.BucketReconcilerOptions{
		RateLimiter: helper.GetRateLimiter(rateLimiterOptions),
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", v1.BucketKind)
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	go func() {
		// Block until our controller manager is elected leader. We presume our
		// entire process will terminate if we lose leadership, so we don't need
		// to handle that.
		<-mgr.Elected()

		startFileServer(storage.BasePath, storageAddr)
	}()

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func startFileServer(path string, address string) {
	setupLog.Info("starting file server")
	fs := http.FileServer(http.Dir(path))
	mux := http.NewServeMux()
	mux.Handle("/", fs)
	err := http.ListenAndServe(address, mux)
	if err != nil {
		setupLog.Error(err, "file server error")
	}
}

func mustSetupEventRecorder(mgr ctrl.Manager, eventsAddr, controllerName string) record.EventRecorder {
	eventRecorder, err := events.NewRecorder(mgr, ctrl.Log, eventsAddr, controllerName)
	if err != nil {
		setupLog.Error(err, "unable to create event recorder")
		os.Exit(1)
	}
	return eventRecorder
}

func mustSetupManager(metricsAddr, healthAddr string, maxConcurrent int,
	watchOpts helper.WatchOptions, clientOpts client.Options, leaderOpts leaderelection.Options) ctrl.Manager {

	watchNamespace := ""
	if !watchOpts.AllNamespaces {
		watchNamespace = os.Getenv("RUNTIME_NAMESPACE")
	}

	watchSelector, err := helper.GetWatchSelector(watchOpts)
	if err != nil {
		setupLog.Error(err, "unable to configure watch label selector for manager")
		os.Exit(1)
	}

	var disableCacheFor []ctrlclient.Object
	shouldCache, err := features.Enabled(features.CacheSecretsAndConfigMaps)
	if err != nil {
		setupLog.Error(err, "unable to check feature gate "+features.CacheSecretsAndConfigMaps)
		os.Exit(1)
	}
	if !shouldCache {
		disableCacheFor = append(disableCacheFor, &corev1.Secret{}, &corev1.ConfigMap{})
	}

	leaderElectionId := fmt.Sprintf("%s-%s", controllerName, "leader-election")
	if watchOpts.LabelSelector != "" {
		leaderElectionId = leaderelection.GenerateID(leaderElectionId, watchOpts.LabelSelector)
	}

	restConfig := client.GetConfigOrDie(clientOpts)
	mgrConfig := ctrl.Options{
		Scheme:                        scheme,
		HealthProbeBindAddress:        healthAddr,
		LeaderElection:                leaderOpts.Enable,
		LeaderElectionReleaseOnCancel: leaderOpts.ReleaseOnCancel,
		LeaseDuration:                 &leaderOpts.LeaseDuration,
		RenewDeadline:                 &leaderOpts.RenewDeadline,
		RetryPeriod:                   &leaderOpts.RetryPeriod,
		LeaderElectionID:              leaderElectionId,
		Logger:                        ctrl.Log,
		Client: ctrlclient.Options{
			Cache: &ctrlclient.CacheOptions{
				DisableFor: disableCacheFor,
			},
		},
		Cache: ctrlcache.Options{
			ByObject: map[ctrlclient.Object]ctrlcache.ByObject{
				&v1.Bucket{}: {Label: watchSelector},
			},
		},
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			ExtraHandlers: pprof.GetHandlers(),
		},
		Controller: ctrlcfg.Controller{
			RecoverPanic:            ptr.To(true),
			MaxConcurrentReconciles: maxConcurrent,
		},
	}

	if watchNamespace != "" {
		mgrConfig.Cache.DefaultNamespaces = map[string]ctrlcache.Config{
			watchNamespace: ctrlcache.Config{},
		}
	}

	mgr, err := ctrl.NewManager(restConfig, mgrConfig)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	return mgr
}

func mustInitStorage(path string, storageAdvAddr string, artifactRetentionTTL time.Duration, artifactRetentionRecords int, artifactDigestAlgo string) *controller.Storage {
	if storageAdvAddr == "" {
		storageAdvAddr = determineAdvStorageAddr(storageAdvAddr)
	}

	if artifactDigestAlgo != intdigest.Canonical.String() {
		algo, err := intdigest.AlgorithmForName(artifactDigestAlgo)
		if err != nil {
			setupLog.Error(err, "unable to configure canonical digest algorithm")
			os.Exit(1)
		}
		intdigest.Canonical = algo
	}

	storage, err := controller.NewStorage(path, storageAdvAddr, artifactRetentionTTL, artifactRetentionRecords)
	if err != nil {
		setupLog.Error(err, "unable to initialise storage")
		os.Exit(1)
	}
	return storage
}

func determineAdvStorageAddr(storageAddr string) string {
	host, port, err := net.SplitHostPort(storageAddr)
	if err != nil {
		setupLog.Error(err, "unable to parse storage address")
		os.Exit(1)
	}
	switch host {
	case "":
		host = "localhost"
	case "0.0.0.0":
		host = os.Getenv("HOSTNAME")
		if host == "" {
			hn, err := os.Hostname()
			if err != nil {
				setupLog.Error(err, "0.0.0.0 specified in storage addr but hostname is invalid")
				os.Exit(1)
			}
			host = hn
		}
	}
	return net.JoinHostPort(host, port)
}

func envOrDefault(envName, defaultValue string) string {
	ret := os.Getenv(envName)
	if ret != "" {
		return ret
	}

	return defaultValue
}
