package docker

import (
	"fmt"

	dfUtils "github.com/deepfence/df-utils"

	humanize "github.com/dustin/go-humanize"
	docker_client "github.com/fsouza/go-dockerclient"

	"net"
	"os"
	"strings"
	"time"

	"github.com/weaveworks/scope/probe"
	"github.com/weaveworks/scope/report"
)

// Keys for use in Node
const (
	ImageID          = report.DockerImageID
	ImageName        = report.DockerImageName
	ImageTag         = report.DockerImageTag
	ImageSize        = report.DockerImageSize
	ImageVirtualSize = report.DockerImageVirtualSize
	IsInHostNetwork  = report.DockerIsInHostNetwork
	UserDfndTags     = "user_defined_tags"
	IsUiVm           = "is_ui_vm"
	ImageLabelPrefix = report.DockerImageLabelPrefix
	ImageTableID     = "image_table"
	ServiceName      = report.DockerServiceName
	StackNamespace   = report.DockerStackNamespace
	DefaultNamespace = report.DockerDefaultNamespace
	ImageCreatedAt   = report.DockerImageCreatedAt
	k8sClusterId     = report.KubernetesClusterId
	k8sClusterName   = report.KubernetesClusterName
)

// Exposed for testing
var (
	ContainerMetadataTemplates = report.MetadataTemplates{
		ImageTag:            {ID: ImageTag, Label: "Image tag", From: report.FromLatest, Priority: 1},
		ImageName:           {ID: ImageName, Label: "Image name", From: report.FromLatest, Priority: 2},
		ContainerCommand:    {ID: ContainerCommand, Label: "Command", From: report.FromLatest, Priority: 3},
		ContainerStateHuman: {ID: ContainerStateHuman, Label: "State", From: report.FromLatest, Priority: 4},
		ContainerUptime:     {ID: ContainerUptime, Label: "Uptime", From: report.FromLatest, Priority: 5, Datatype: report.Duration},
		//ContainerRestartCount: {ID: ContainerRestartCount, Label: "Restart #", From: report.FromLatest, Priority: 6},
		ContainerNetworks: {ID: ContainerNetworks, Label: "Networks", From: report.FromSets, Priority: 7},
		ContainerIPs:      {ID: ContainerIPs, Label: "IPs", From: report.FromSets, Priority: 8},
		ContainerPorts:    {ID: ContainerPorts, Label: "Ports", From: report.FromSets, Priority: 9},
		ContainerCreated:  {ID: ContainerCreated, Label: "Created", From: report.FromLatest, Datatype: report.DateTime, Priority: 10},
		ContainerID:       {ID: ContainerID, Label: "ID", From: report.FromLatest, Truncate: 12, Priority: 11},
		UserDfndTags:      {ID: UserDfndTags, Label: "User Defined Tags", From: report.FromLatest, Priority: 12},
		IsUiVm:            {ID: IsUiVm, Label: "UI vm", From: report.FromLatest, Priority: 13},
		ImageID:           {ID: ImageID, Label: "Image ID", From: report.FromLatest, Truncate: 12, Priority: 14},
		k8sClusterId:      {ID: k8sClusterId, Label: "Kubernetes Cluster Id", From: report.FromLatest, Priority: 15},
		k8sClusterName:    {ID: k8sClusterName, Label: "Kubernetes Cluster Name", From: report.FromLatest, Priority: 16},
	}

	ContainerMetricTemplates = report.MetricTemplates{
		CPUTotalUsage: {ID: CPUTotalUsage, Label: "CPU", Format: report.PercentFormat, Priority: 1},
		MemoryUsage:   {ID: MemoryUsage, Label: "Memory", Format: report.FilesizeFormat, Priority: 2},
	}

	ContainerImageMetadataTemplates = report.MetadataTemplates{
		report.Container: {ID: report.Container, Label: "# Containers", From: report.FromCounters, Datatype: report.Number, Priority: 2},
		UserDfndTags:     {ID: UserDfndTags, Label: "User Defined Tags", From: report.FromLatest, Priority: 3},
		ImageName:        {ID: ImageName, Label: "Image name", From: report.FromLatest, Priority: 4},
		ImageTag:         {ID: ImageTag, Label: "Image tag", From: report.FromLatest, Priority: 5},
		ImageSize:        {ID: ImageSize, Label: "Image size", From: report.FromLatest, Priority: 6},
		ImageVirtualSize: {ID: ImageVirtualSize, Label: "Image virtual size", From: report.FromLatest, Priority: 7},
		ImageID:          {ID: ImageID, Label: "Image ID", From: report.FromLatest, Truncate: 12, Priority: 8},
		ImageCreatedAt:   {ID: ImageCreatedAt, Label: "Created At", From: report.FromLatest, Priority: 9},
	}

	ContainerTableTemplates = report.TableTemplates{
		ImageTableID: {
			ID:    ImageTableID,
			Label: "Image",
			Type:  report.PropertyListType,
			FixedRows: map[string]string{
				// Prepend spaces as a hack to keep at the top when sorted.
				ImageID:          " ID",
				ImageName:        " Name",
				ImageTag:         " Tag",
				ImageSize:        "Size",
				ImageVirtualSize: "Virtual size",
			},
		},
		LabelPrefix: {
			ID:     LabelPrefix,
			Label:  "Docker labels",
			Type:   report.PropertyListType,
			Prefix: LabelPrefix,
		},
		EnvPrefix: {
			ID:     EnvPrefix,
			Label:  "Environment variables",
			Type:   report.PropertyListType,
			Prefix: EnvPrefix,
		},
	}

	ContainerImageTableTemplates = report.TableTemplates{
		ImageLabelPrefix: {
			ID:     ImageLabelPrefix,
			Label:  "Docker labels",
			Type:   report.PropertyListType,
			Prefix: ImageLabelPrefix,
		},
	}

	SwarmServiceMetadataTemplates = report.MetadataTemplates{
		ServiceName:    {ID: ServiceName, Label: "Service name", From: report.FromLatest, Priority: 0},
		StackNamespace: {ID: StackNamespace, Label: "Stack namespace", From: report.FromLatest, Priority: 1},
	}
)

// Reporter generate Reports containing Container and ContainerImage topologies
type Reporter struct {
	registry              Registry
	hostID                string
	probeID               string
	isUIvm                string
	probe                 *probe.Probe
	kubernetesClusterId   string
	kubernetesClusterName string
}

// NewReporter makes a new Reporter
func NewReporter(registry Registry, hostID string, probeID string, probe *probe.Probe) *Reporter {
	isUIvm := "false"
	if dfUtils.IsThisHostUIMachine() {
		isUIvm = "true"
	}
	reporter := &Reporter{
		registry:              registry,
		hostID:                hostID,
		probeID:               probeID,
		isUIvm:                isUIvm,
		probe:                 probe,
		kubernetesClusterName: os.Getenv(k8sClusterName),
		kubernetesClusterId:   os.Getenv(k8sClusterId),
	}
	registry.WatchContainerUpdates(reporter.ContainerUpdated)
	return reporter
}

// Name of this reporter, for metrics gathering
func (Reporter) Name() string { return "Docker" }

// ContainerUpdated should be called whenever a container is updated.
func (r *Reporter) ContainerUpdated(n report.Node) {
	// Publish a 'short cut' report container just this container
	rpt := report.MakeReport()
	rpt.Shortcut = true
	rpt.Container.AddNode(n)
	r.probe.Publish(rpt)
}

// Report generates a Report containing Container and ContainerImage topologies
func (r *Reporter) Report() (report.Report, error) {
	localAddrs, err := report.LocalAddresses()
	if err != nil {
		return report.MakeReport(), nil
	}

	result := report.MakeReport()
	result.Container = result.Container.Merge(r.containerTopology(localAddrs))
	result.ContainerImage = result.ContainerImage.Merge(r.containerImageTopology())
	result.Overlay = result.Overlay.Merge(r.overlayTopology())
	result.SwarmService = result.SwarmService.Merge(r.swarmServiceTopology())
	return result, nil
}

// Get local addresses both as strings and IP addresses, in matched slices
func getLocalIPs() ([]string, []net.IP, error) {
	ipnets, err := report.GetLocalNetworks()
	if err != nil {
		return nil, nil, err
	}
	ips := []string{}
	addrs := []net.IP{}
	for _, ipnet := range ipnets {
		ips = append(ips, ipnet.IP.String())
		addrs = append(addrs, ipnet.IP)
	}
	return ips, addrs, nil
}

func (r *Reporter) containerTopology(localAddrs []net.IP) report.Topology {
	result := report.MakeTopology().
		WithMetadataTemplates(ContainerMetadataTemplates).
		WithMetricTemplates(ContainerMetricTemplates).
		WithTableTemplates(ContainerTableTemplates)

	metadata := map[string]string{report.ControlProbeID: r.probeID}
	nodes := []report.Node{}
	r.registry.WalkContainers(func(c Container) {
		nodes = append(nodes, c.GetNode().WithLatests(metadata))
	})

	// Copy the IP addresses from other containers where they share network
	// namespaces & deal with containers in the host net namespace.  This
	// is recursive to deal with people who decide to be clever.
	{
		hostNetworkInfo := report.MakeSets()
		if hostStrs, hostIPs, err := getLocalIPs(); err == nil {
			hostIPsWithScopes := addScopeToIPs(r.hostID, hostIPs)
			hostNetworkInfo = hostNetworkInfo.
				Add(ContainerIPs, report.MakeStringSet(hostStrs...)).
				Add(ContainerIPsWithScopes, report.MakeStringSet(hostIPsWithScopes...))
		}

		var networkInfo func(prefix string) (report.Sets, bool)
		networkInfo = func(prefix string) (ips report.Sets, isInHostNamespace bool) {
			container, ok := r.registry.GetContainerByPrefix(prefix)
			if !ok {
				return report.MakeSets(), false
			}

			networkMode, ok := container.NetworkMode()
			if ok && strings.HasPrefix(networkMode, "container:") {
				return networkInfo(networkMode[10:])
			} else if ok && networkMode == "host" {
				return hostNetworkInfo, true
			}

			return container.NetworkInfo(localAddrs), false
		}
		containerImageTags := r.registry.GetContainerTags()
		for _, node := range nodes {
			id, ok := report.ParseContainerNodeID(node.ID)
			if !ok {
				continue
			}
			networkInfo, isInHostNamespace := networkInfo(id)
			node = node.WithSets(networkInfo)
			tags, ok := containerImageTags[id]
			if !ok {
				tags = []string{}
			}
			latest := map[string]string{
				UserDfndTags: strings.Join(tags, ","),
				IsUiVm:       r.isUIvm,
				"host_name":  r.hostID,
			}
			// Indicate whether the container is in the host network
			// The container's NetworkMode is not enough due to
			// delegation (e.g. NetworkMode="container:foo" where
			// foo is a container in the host networking namespace)
			if isInHostNamespace {
				latest[IsInHostNetwork] = "true"
			}
			if r.kubernetesClusterName != "" {
				latest[k8sClusterName] = r.kubernetesClusterName
			}
			if r.kubernetesClusterId != "" {
				latest[k8sClusterId] = r.kubernetesClusterId
			}
			node = node.WithLatests(latest)
			result.AddNode(node)

		}
	}

	return result
}

func (r *Reporter) containerImageTopology() report.Topology {
	result := report.MakeTopology().
		WithMetadataTemplates(ContainerImageMetadataTemplates).
		WithTableTemplates(ContainerImageTableTemplates)

	imageTagsMap := r.registry.GetImageTags()
	r.registry.WalkImages(func(image docker_client.APIImages) {
		imageID := trimImageID(image.ID)
		latests := map[string]string{
			ImageID:          imageID,
			ImageSize:        humanize.Bytes(uint64(image.Size)),
			ImageVirtualSize: humanize.Bytes(uint64(image.VirtualSize)),
			ImageCreatedAt:   time.Unix(image.Created, 0).Format("2006-01-02T15:04:05") + "Z",
		}
		if len(image.RepoTags) > 0 {
			imageFullName := image.RepoTags[0]
			latests[ImageName] = ImageNameWithoutTag(imageFullName)
			latests[ImageTag] = ImageNameTag(imageFullName)
		}
		nodeID := report.MakeContainerImageNodeID(imageID)
		var tags []string
		var ok bool
		if latests[ImageName] != "" {
			tags, ok = imageTagsMap[fmt.Sprintf("%s:%s", latests[ImageName], latests[ImageTag])]
			if !ok {
				tags = []string{}
			}
		}
		latests[UserDfndTags] = strings.Join(tags, ",")
		node := report.MakeNodeWith(nodeID, latests)
		node = node.AddPrefixPropertyList(ImageLabelPrefix, image.Labels)
		result.AddNode(node)
	})

	return result
}

func (r *Reporter) overlayTopology() report.Topology {
	subnets := []string{}
	r.registry.WalkNetworks(func(network docker_client.Network) {
		for _, config := range network.IPAM.Config {
			subnets = append(subnets, config.Subnet)
		}

	})
	// Add both local and global networks to the LocalNetworks Set
	// since we treat container IPs as local
	node := report.MakeNode(report.MakeOverlayNodeID(report.DockerOverlayPeerPrefix, r.hostID)).WithSets(
		report.MakeSets().Add(report.HostLocalNetworks, report.MakeStringSet(subnets...)))
	t := report.MakeTopology()
	t.AddNode(node)
	return t
}

func (r *Reporter) swarmServiceTopology() report.Topology {
	return report.MakeTopology().WithMetadataTemplates(SwarmServiceMetadataTemplates)
}

// Docker sometimes prefixes ids with a "type" annotation, but it renders a bit
// ugly and isn't necessary, so we should strip it off
func trimImageID(id string) string {
	return strings.TrimPrefix(id, "sha256:")
}
